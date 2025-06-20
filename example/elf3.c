#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h" ns

#define PAGE_SIZE 0x1000

int main() {
    // --- Assembly code: calls printf through PLT and then exits ---
    // This code snippet is designed to:
    // 1. Load the address of the "Hello world" string into RDI (for printf's first argument).
    // 2. Zero out EAX (required for printf's calling convention on x64).
    // 3. Call printf via its PLT entry.
    // 4. Zero out EDI (for sys_exit's status code 0).
    // 5. Set EAX to 60 (syscall number for sys_exit).
    // 6. Execute the syscall to exit.
    uint8_t code[] = {
        0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string> (10 bytes)
        0x31, 0xc0,                   // xor eax, eax (2 bytes, for printf's %eax = 0)
        0xe8, 0,0,0,0,                // call printf@plt (5 bytes)
        0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string> (10 bytes)
        0xe8, 0,0,0,0,                // call puts@plt (5 bytes)
        0x31, 0xff,                   // xor edi, edi (2 bytes, for sys_exit's %edi = 0 status)
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (sys_exit) (5 bytes)
        0x0f, 0x05                    // syscall (2 bytes)
    };

    const char hello_str[] = "Hello world\n";  // String to print, includes null terminator
    const char interp[] = "/lib64/ld-linux-x86-64.so.2"; // Dynamic linker path
    // Dynamic string table: null byte, "printf", null byte, "libc.so.6", null byte
    // The null bytes are crucial string terminators.
    const char dynstr[] = "\0printf\0puts\0libc.so.6\0";

    size_t code_size = sizeof(code);
    size_t data_size = sizeof(hello_str); // Includes null terminator

    uint64_t base_vaddr = 0x400000; // Base virtual address for loading the executable
    size_t capacity = 16 * PAGE_SIZE; // Sufficient capacity for the ELF file (16 pages)
    ElfBuilder *b = elf_builder_create_exec64(capacity, 5);

    if (!b) {
        fprintf(stderr, "Error creating ELF builder\n");
        return 1;
    }

    // Program headers are placed immediately after Elf64_Ehdr.
    // `b->phdr` already points to this memory location within `b->mem`.
    Elf64_Phdr *phdr = (Elf64_Phdr *)b->phdr;
    // Clear the program header entries to ensure a clean state before populating them.
    // This is important as calloc might only zero the initial structures.
    memset(phdr, 0, b->phnum * sizeof(Elf64_Phdr));


    // `current_file_offset` tracks the current write position in the ELF file's memory buffer.
    // It starts after the ELF header and program headers, which are at the beginning (offset 0).
    size_t current_file_offset = b->size;

    // Ensure the `.text` section starts at a page-aligned offset (typical for executable segments).
    // The ELF header and program headers occupy the first part of the first page.
    if (current_file_offset % PAGE_SIZE != 0) {
        size_t padding = PAGE_SIZE - (current_file_offset % PAGE_SIZE);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset; // Update builder's size to reflect padding
    }


    // Add .text section (executable code)
    size_t text_section_off;     // File offset of .text section
    uint64_t text_section_vaddr; // Virtual address of .text section
    size_t idx_text = elf_builder_add_section_ex(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, // Type, Flags (Allocatable, Executable)
        code, code_size, base_vaddr + current_file_offset, 16, // Data, Size, Virtual Address, Alignment
        &text_section_off, &text_section_vaddr, 0, 0, 0 // Extended fields (link, info, entsize)
    );
    current_file_offset = b->size; // Update current_file_offset after adding .text

    /**
     * Las entradas a la PLT, ocupan 16bytes, no creo que se pueda definir campos mas grandes
     * y menores no permitirian que las entradas esten alineadas, asi que el linker dinamico
     * exije este tamaño.
     *
     * Las entradas en 32bits para x86 no cambian demasiado:
     * <printf@plt>:
     *      jmp DWORD PTR [<dirección_en_GOT>]   ; 1. Salta a la dirección almacenada en la GOT
     *      push <relocation_index>              ; 2. Apila el índice de relocalización
     *      jmp <plt0>                           ; 3. Salta al inicio de la PLT (PLT0)
     */
    typedef struct plt_entry_t{
        union {
            uint8_t jmp_got[6];                 // jmp QWORD PTR [rip + offset_to_GOT]
            struct {
                uint16_t opcode_jmp_got_rip;    // opcode 0xff, 0x25 == jmp QWORD PTR
                uint32_t offset_jmp_got;        // [rip + offset_to_GOT]
            };
        };
        union {
            uint8_t push[5];                    // push <relocation_index>
            struct {
                uint8_t opcode_push;            // 0x68 opcode == push
                uint32_t offset_got;            // relocation_index
            };
        };
        union {
            uint8_t jmp_plt[5];                 // jmp <plt0>
            struct {
                uint8_t opcode_jmp_plt;         // opcode 0xff, 0x25 == jmp QWORD PTR
                uint32_t offset_jmp_plt_got;    // [rip + offset_to_GOT]
            };
        };
    } plt_entry_t;

    // Add .plt section (Procedure Linkage Table)
    // This defines the PLT0 (global entry) and PLT1 (printf specific entry).
    // PLT0 handles initial dynamic linker setup.
    // PLT1 handles lazy symbol resolution for printf.
    uint8_t plt_code[] = {
        // PLT0 (Offset 0 in .plt section, used for dynamic linker setup)
        // push QWORD PTR [rip+GOT[1]_offset]
        // This pushes the link_map pointer (GOT[1]) onto the stack.
        0xff, 0x35, 0,0,0,0,
        // jmp QWORD PTR [rip+GOT[2]_offset]
        // This jumps to the _dl_runtime_resolve function provided by the dynamic linker (GOT[2]).
        0xff, 0x25, 0,0,0,0,
        0x0f, 0x1f, 0x40, 0x00,          // nop dword ptr [rax+0x0] (padding for 16-byte alignment)

        // PLT1 (printf@plt, Offset 16 in .plt section)
        // jmp QWORD PTR [rip+GOT_printf_offset]
        // Initially, GOT_printf_offset points back into this stub. After resolution, it points to actual printf.
        0xff, 0x25, 0,0,0,0,
        // pushq <relocation index for printf>
        // Pushes the index of the printf entry in .rela.plt (which is 0 in our case).
        0x68, 0x00,0x00,0x00,0x00,
        // jmp .plt[0]
        // Jumps back to PLT0 to initiate symbol resolution.
        0xe9, 0,0,0,0,

        // PLT2 (puts@plt, Offset 32 in .plt section)
        0xff, 0x25, 0,0,0,0,
        0x68, 0x01,0x00,0x00,0x00, // pushq 1   Indice de relocalización (1 para puts)
        0xe9, 0,0,0,0
    };

    size_t plt_section_off;
    uint64_t plt_section_vaddr;
    elf_builder_add_section_ex(
        b, ".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        plt_code, sizeof(plt_code), base_vaddr + current_file_offset, 16,
        &plt_section_off, &plt_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size; // Update current_file_offset after adding .plt

    // Calculate the end of the first (executable) segment in the file.
    // This segment will cover the ELF header, program headers, .text, and .plt.
    size_t rx_seg_file_end_offset = current_file_offset;


    // Ensure the Read-Write sections (.data, .got.plt, .dynamic) start at a new page boundary.
    if (current_file_offset % PAGE_SIZE != 0) {
        size_t padding = PAGE_SIZE - (current_file_offset % PAGE_SIZE);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset; // Update builder's size
    }


    // Add .data section (writable data, holds our "Hello world" string)
    size_t data_section_off;
    uint64_t data_section_vaddr;
    elf_builder_add_section_ex(
        b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, // Type, Flags (Allocatable, Writable)
        hello_str, data_size, base_vaddr + current_file_offset, 8, // Data, Size, Virtual Address, Alignment
        &data_section_off, &data_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size; // Update current_file_offset


    // Properly align .got.plt (Global Offset Table for PLT), typically 8-byte aligned.
    if (current_file_offset % 8 != 0) {
        size_t padding = 8 - (current_file_offset % 8);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }
    // Add .got.plt section
    // GOT[0] Dirección de la sección .dynamic (usada internamente por el dynamic linker).
    // GOT[1] Puntero a la estructura link_map (usada internamente por el dynamic linker)
    // GOT[2] Puntero a la función de resolución (_dl_runtime_resolve)
    // GOT[3] is the entry for `printf` (initially points into PLT, then resolved at runtime).
    // GOT[4] is the entry for `puts`
    uint64_t got_plt[5] = {0}; // Initialize all entries to 0

    size_t got_plt_section_off;
    uint64_t got_plt_section_vaddr;
    elf_builder_add_section_ex(
        b, ".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, // Type, Flags (Allocatable, Writable)
        got_plt, sizeof(got_plt), // Data, Size
        base_vaddr + current_file_offset, 0x1000, // Virtual Address, Alignment
        &got_plt_section_off, &got_plt_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size;


    // Patch the string address into the `mov rdi` instruction in the code.
    // The instruction `mov rdi, QWORD imm64` is 10 bytes long.
    // The immediate starts at offset 2 within the instruction.
    *(uint64_t *)(b->mem + text_section_off + 2)  = data_section_vaddr;
    *(uint64_t *)(b->mem + text_section_off + 19) = data_section_vaddr;


    // Add .interp section (Program interpreter path)
    // Contains the path to the dynamic linker (e.g., /lib64/ld-linux-x86-64.so.2).
    // No specific alignment required, typically 1-byte aligned.
    if (current_file_offset % 8 != 0) {
        size_t padding = 8 - (current_file_offset % 8);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }
    size_t interp_section_off;
    uint64_t interp_section_vaddr;
    elf_builder_add_section_ex(
        b, ".interp", SHT_PROGBITS, SHF_ALLOC, // Type, Flags (Allocatable)
        interp, sizeof(interp), base_vaddr + current_file_offset, 1, // Data, Size, Virtual Address, Alignment
        &interp_section_off, &interp_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size;


    // Add .dynstr section (Dynamic string table)
    // Contains names for dynamic symbols (like "printf") and shared libraries (like "libc.so.6").
    // 1-byte aligned for string table.
    if (current_file_offset % 1 != 0) {
        size_t padding = 1 - (current_file_offset % 1);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }
    size_t dynstr_section_off;
    uint64_t dynstr_section_vaddr;
    size_t dynstr_size = sizeof(dynstr);
    size_t idx_dynstr = elf_builder_add_section_ex(
        b, ".dynstr", SHT_STRTAB, SHF_ALLOC, // Type, Flags (Allocatable)
        dynstr, dynstr_size, // Data, Size
        base_vaddr + current_file_offset, 8, // Virtual Address, Alignment
        &dynstr_section_off, &dynstr_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size;


    // Align before .dynsym (Dynamic Symbol Table), typically 8-byte aligned.
    if (current_file_offset % 8 != 0) {
        size_t padding = 8 - (current_file_offset % 8);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }
    // Add .dynsym section
    Elf64_Sym dynsym[3] = {0}; // Array for dynamic symbols
    // dynsym[0]: Null symbol (mandatory first entry)
    dynsym[0].st_name = 0;
    dynsym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    dynsym[0].st_shndx = SHN_UNDEF;
    // dynsym[1]: printf symbol
    // st_name = 1: offset in .dynstr for "printf" (which is after the initial null byte in dynstr[])
    dynsym[1].st_name = 1;
    dynsym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); // Global, Function type
    dynsym[1].st_shndx = SHN_UNDEF; // Undefined section, resolved at runtime by dynamic linker

    // dynsym[2]: puts symbol
    // st_name = 1: offset in .dynstr for "puts"
    dynsym[2].st_name = sizeof("\0printf"); // obtenemos el offset para puts
    dynsym[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); // Global, Function type
    dynsym[2].st_shndx = SHN_UNDEF; // Undefined section, resolved at runtime by dynamic linker

    size_t dynsym_section_off;
    uint64_t dynsym_section_vaddr;
    size_t idx_dynsym = elf_builder_add_section_ex(
        b, ".dynsym", SHT_DYNSYM, SHF_ALLOC, // Type, Flags (Allocatable)
        dynsym, sizeof(dynsym[0]) * 3 , // Data, Size
        base_vaddr + current_file_offset, 8, // Virtual Address, Alignment
        &dynsym_section_off, &dynsym_section_vaddr,
        idx_dynstr, // sh_link: link to .dynstr (for names)
        1,          // sh_info: index of first non-local symbol (printf is at index 1)
        sizeof(Elf64_Sym) // sh_entsize: size of each entry
    );
    current_file_offset = b->size;




    // Align before .rela.plt (Relocation Entries with Addend for PLT), typically 8-byte aligned.
    if (current_file_offset % 8 != 0) {
        size_t padding = 8 - (current_file_offset % 8);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }
    // Add .rela.plt section
    Elf64_Rela rela[2] = {0}; // Single relocation entry for printf
    // r_offset: Virtual address of GOT[3] (where the resolved printf address will be stored)
    rela[0].r_offset = got_plt_section_vaddr + 3 * 8;
    // r_info: Combines symbol index (1 for printf) and relocation type (R_X86_64_JUMP_SLOT)
    rela[0].r_info = ELF64_R_INFO(1, R_X86_64_JUMP_SLOT);
    rela[0].r_addend = 0; // No addend typically for JUMP_SLOT

    // r_offset: Virtual address of GOT[4] (where the resolved printf address will be stored)
    rela[1].r_offset = got_plt_section_vaddr + 4 * 8;
    // r_info: Combines symbol index (2 for puts) and relocation type (R_X86_64_JUMP_SLOT)
    rela[1].r_info = ELF64_R_INFO(2, R_X86_64_JUMP_SLOT);
    rela[1].r_addend = 0; // No addend typically for JUMP_SLOT

    size_t rela_plt_section_off;
    uint64_t rela_plt_section_vaddr;
    elf_builder_add_section_ex(
        b, ".rela.plt", SHT_RELA, SHF_ALLOC, // Type, Flags (Allocatable)
        &rela, sizeof(rela[0]) * 2, // Data, Size
        base_vaddr + current_file_offset, 8, // Virtual Address, Alignment
        &rela_plt_section_off, &rela_plt_section_vaddr,
        idx_dynsym, // sh_link: link to .dynsym
        0,          // sh_info: No specific meaning here, usually 0
        sizeof(Elf64_Rela) // sh_entsize: size of each entry
    );
    current_file_offset = b->size;


    // Align before .dynamic (Dynamic Section), typically 16-byte aligned.
    if (current_file_offset % 16 != 0) {
        size_t padding = 16 - (current_file_offset % 16);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset;
    }

    // Add .dynamic section
    // This table provides information to the dynamic linker.
    Elf64_Dyn dynamic[] = {
        {DT_NEEDED,   {.d_val = sizeof("\0print\0puts\0")}},                  // Offset of "libc.so.6" in .dynstr
        {DT_PLTGOT,   {.d_ptr = got_plt_section_vaddr}}, // Virtual Address of .got.plt
        {DT_STRTAB,   {.d_ptr = dynstr_section_vaddr}},  // Virtual Address of .dynstr
        {DT_SYMTAB,   {.d_ptr = dynsym_section_vaddr}},  // Virtual Address of .dynsym
        {DT_STRSZ,    {.d_val = dynstr_size}},         // Size of .dynstr
        {DT_SYMENT,   {.d_val = sizeof(Elf64_Sym)}},   // Size of a .dynsym entry
        {DT_PLTRELSZ, {.d_val = sizeof(rela)}},        // Size of .rela.plt
        {DT_PLTREL,   {.d_val = DT_RELA}},             // Relocations for PLT are type RELA
        {DT_JMPREL,   {.d_ptr = rela_plt_section_vaddr}},// Virtual Address of .rela.plt (same as DT_RELA for JUMP_SLOT)
        {DT_RELA,     {.d_ptr = rela_plt_section_vaddr}},// Virtual Address of .rela (same in this simple case)
        {DT_RELASZ,   {.d_val = sizeof(rela)}},        // Size of .rela
        {DT_RELAENT,  {.d_val = sizeof(Elf64_Rela)}},  // Size of a .rela entry
        {DT_NULL,     {.d_val = 0}}                     // End of dynamic section (mandatory)
    };

    size_t dynamic_section_off;
    uint64_t dynamic_section_vaddr;
    elf_builder_add_section_ex(
        b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, // Type, Flags (Allocatable, Writable)
        dynamic, sizeof(dynamic), base_vaddr + current_file_offset, 8, // Data, Size, Virtual Address, Alignment
        &dynamic_section_off, &dynamic_section_vaddr,
        idx_dynstr, // sh_link: link to .dynstr
        0,          // sh_info: No specific meaning
        sizeof(Elf64_Dyn) // sh_entsize: size of each entry
    );
    current_file_offset = b->size;


    /**
     * Entrada GOT	Contenido inicial	            ¿Quién lo actualiza?	    Ejemplo en el dump
     * GOT[0]   	.dynamic	                    Tu código	                0x004030a0
     * Despues de ejecutar el codigo, el linker pondra lo siguiente en la GOT[0]
     * GOT[0]   	_dl_runtime_resolve	            Dynamic linker	            0x00000000
     * GOT[1]   	link_map (usado por el linker)	Dynamic linker	            0x00000000
     * GOT[2]   	PLT de printf	                Tu código (luego el linker)	0x401030
     * GOT[3]   	PLT de puts  	                Tu código (luego el linker)
     *
     * PLT0 (offset 0):
     *      - Dirección: plt_section_vaddr + 0
     *      - Tamaño: 16 bytes (contando el padding)
     * PLT1 (offset 16):
     *      - Dirección: plt_section_vaddr + 16
     *      - Tamaño: 16 bytes (en este caso, aunque puede variar según el código generado)
     */

    // pondremos la seccion .dynamic, la necesita el linker
    ((uint64_t *)(b->mem + got_plt_section_off))[0] = dynamic_section_vaddr;

    /* Inicialmente apunta a la PLT, luego el dynamic linker lo actualiza:
     * La entrada global (PLT0) ocupa 16 bytes,
     * la entrada para printf (PLT1) empieza justo después, en el offset 16,
     * por lo que, plt_section_vaddr + 16 es la dirección de la entrada PLT para printf.
     */
    printf("plt_section_vaddr + 16 * 1 == %x\n", plt_section_vaddr + 16 * 1);
    ((uint64_t *)(b->mem + got_plt_section_off))[3] = plt_section_vaddr + 16 * 1 + 6;


    /**
     *   0000000000401040 <printf@plt>:
     *      401040:       ff 25 d2 1f 00 00       jmp    *0x1fd2(%rip)        # 403018 <puts@plt+0x1fc8>
     *      401046:       68 00 00 00 00          push   $0x0
     *      40104b:       e9 e0 ff ff ff          jmp    401030 <_start+0x30>
     *      
     *  Como la GOT apuntara a su PLT(PLT[1] para printf):
     *          GOT[3](0x403018) = PLT[1](0x401040)
     *  Debemos evitar que nuestra entrada a la got, apunte al principio de la entrada de la PLT, esto es asi
     *  por que, la primera instruccion de la PLT, es un "jmp    *0x1fd2(%rip) #403018"(GOT[3] == 0x403018),
     *  si al saltar a la GOT la GOT vuelve a apuntar a este salto, se genera un bucle infinito, por eso
     *  sumamos 6 al calculo, ya que la instruccion de salto ocupa 6 bytes.
     *  Siendo el calculo el siguiente
     *  base_address_PLT_section + 16(tamaño de cada entrada de la PLT) * index_PLT(indice de la entrada a la PLT) +
     *      6 (bytes que ocupa la instruccion jmp).
     */
    printf("plt_section_vaddr + 16 * 1 == %x\n", plt_section_vaddr + 16 * 2);
    ((uint64_t *)(b->mem + got_plt_section_off))[4] = plt_section_vaddr + 16 * 2 + 6;

    printf("b->mem + got_plt_section_off == %x\n", base_vaddr + got_plt_section_off);

    printf("b->mem + [[3]] == %x\n", (((void *)&((uint64_t *)(b->mem + got_plt_section_off))[3]) - (void *)(b->mem + got_plt_section_off)));
    printf("b->mem + [[4]] == %x\n", (((void *)&((uint64_t *)(b->mem + got_plt_section_off))[4]) - (void *)(b->mem + got_plt_section_off)));


    // Add .strtab section (String Table for non-dynamic symbols, e.g., `_start`)
    // Not loaded into memory by the OS loader, but used by tools like objdump/readelf.
    const char strtab[] = "\0_start\0"; // Contains symbol "_start"
    size_t strtab_size = sizeof(strtab);
    size_t strtab_section_off;
    uint64_t strtab_section_vaddr; // Will be 0 as not allocatable
    size_t idx_strtab = elf_builder_add_section_ex(
        b, ".strtab", SHT_STRTAB, 0, // Not SHF_ALLOC as it's not loaded into memory for execution
        strtab, strtab_size, // Data, Size
        0,
        1, // No virtual address, 1-byte alignment
        &strtab_section_off, &strtab_section_vaddr, 0, 0, 0
    );
    current_file_offset = b->size;


    // Add .symtab section (Symbol Table for non-dynamic symbols)
    // Also not loaded into memory, used by tools.
    Elf64_Sym symtab[2] = {0}; // Array for symbol table entries
    // symtab[0]: Null symbol (mandatory first entry)
    symtab[0].st_name = 0;
    symtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    symtab[0].st_shndx = SHN_UNDEF;

    // symtab[1]: _start symbol (the entry point of our executable)
    symtab[1].st_name = 1; // Offset of "_start" in .strtab
    symtab[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); // Global, Function type
    symtab[1].st_shndx = idx_text; // Section index of .text (retrieved from elf_builder_add_section_ex)
    symtab[1].st_value = text_section_vaddr; // Virtual address of _start
    symtab[1].st_size = code_size; // Size of the _start function (our `code` array)

    size_t symtab_section_off;
    uint64_t symtab_section_vaddr; // Will be 0 as not allocatable
    elf_builder_add_section_ex(
        b, ".symtab", SHT_SYMTAB, 0, // Not SHF_ALLOC
        symtab, sizeof(symtab), // Data, Size
        0, 8, // No virtual address, 8-byte alignment
        &symtab_section_off, &symtab_section_vaddr,
        idx_strtab, // sh_link: link to .strtab (for names)
        1,          // sh_info: index of first non-local symbol (_start is at index 1)
        sizeof(Elf64_Sym) // sh_entsize: size of each entry
    );
    current_file_offset = b->size;


    // --- Patching the PLT stubs' relative offsets ---

    // Patch the call to printf@plt in the code (`0xe8, 0,0,0,0`)
    // The call instruction is at `text_section_vaddr + 12`.
    // The relative offset is calculated from the *address of the instruction's operand*, which is `call_instruction_vaddr + 1`.
    // The RIP register, when calculating the relative jump, points to the instruction *after* the current one.
    // A 5-byte call instruction: `0xE8 [offset_bytes]`
    // `rip` will be `(text_section_vaddr + 12) + 5` after the call instruction executes.
    uint64_t call_instruction_vaddr = text_section_vaddr + 12; // calculamos la instruccion a modificar
    // calculamos la entrada de la PLT que resolvera el simbolo, "printf" en este caso, la cual es PLT[1]
    uint64_t plt1_entry_vaddr = plt_section_vaddr + 16 * 1;

    // rel32_printf_call = plt1_entry_vaddr - (call_instruction_vaddr + 5)
    // offset            = destino          - (dirección_de_la_siguiente_instrucción)
    // se debe calcular un desplazamiento, pues el call usado, no salta a una direccion absoluta, sino un offset
    // especifico, para saber esto calcula cuántos bytes hay que saltar (hacia adelante o hacia atrás)
    // desde la instrucción siguiente al call hasta la entrada PLT de printf
    int32_t rel32_printf_call                    = (int32_t) (plt1_entry_vaddr - (call_instruction_vaddr + 5));

    // parchear la instruccion call con el offset relativo a la funcion de la PLT obtenida anteriomente.
    *(int32_t *)(b->mem + text_section_off + 13) = rel32_printf_call; // Offset 13 within code[] for the 4-byte operand


    // Patch offsets in PLT stubs' instructions for position-independent code (PIC)
    // PLT0: `push QWORD PTR [rip+X]` (points to GOT+8, i.e., GOT[1])
    // Instruction `0xff, 0x35` is at `plt_section_off + 0`. It's 6 bytes long.
    // `RIP` will be `plt_section_vaddr + 6`. Target is `got_plt_section_vaddr + 8`.
    *(int32_t *)(b->mem + plt_section_off + 2) = (int32_t)((got_plt_section_vaddr + 8 * 1) - (plt_section_vaddr + 6));

    // PLT0: `jmp  QWORD PTR [rip+Y]` (points to GOT+16, i.e., GOT[2])
    // Instruction `0xff, 0x25` is at `plt_section_off + 6`. It's 6 bytes long.
    // `RIP` will be `plt_section_vaddr + 6 + 6 = plt_section_vaddr + 12`. Target is `got_plt_section_vaddr + 16`.
    *(int32_t *)(b->mem + plt_section_off + 8) = (int32_t)((got_plt_section_vaddr + 8 * 2) - (plt_section_vaddr + 12));

    // PLT1 (printf stub): `jmp QWORD PTR [rip+Z]` (points to GOT+24, i.e., GOT[3], for printf's resolved address)
    // Instruction `0xff, 0x25` is at `plt_section_off + 24`. It's 6 bytes long.
    // `RIP` will be `plt_section_vaddr + 24 + 6 = plt_section_vaddr + 22`. Target is `got_plt_section_vaddr + 16`.
    *(int32_t *)(b->mem + plt_section_off + 18) = (int32_t)((got_plt_section_vaddr + 8*3) - (plt_section_vaddr + 22));

    // PLT1 (printf stub): `pushq <relocation index>`
    // The relocation index for `printf` in our `.rela.plt` section is 0 (as it's the first and only entry).
    // The `pushq` opcode (0x68) is at plt_section_off + 22. Its 4-byte operand starts at plt_section_off + 23.
    *(uint32_t *)(b->mem + plt_section_off + 23) = 0; // Corrected offset

    // PLT1 (printf stub): `jmp .plt[0]` (jump back to the global PLT entry PLT0)
    // Instruction `0xe9` is at `plt_section_off + 27`. It's 5 bytes long.
    // The operand starts at plt_section_off + 28.
    // `RIP` after instruction is `plt_section_vaddr + 27 + 5 = plt_section_vaddr + 32`.
    // Target is `plt_section_vaddr` (PLT0 start).
    // Relative offset = Target - RIP_after_instruction = plt_section_vaddr - (plt_section_vaddr + 32) = -32.
    *(int32_t *)(b->mem + plt_section_off + 28) = (int32_t)(plt_section_vaddr - (plt_section_vaddr + 32)); // Corrected offset and value



    uint64_t call_instruction_vaddr_puts = text_section_vaddr + 24; // calculamos la instruccion a modificar
    uint64_t plt2_entry_vaddr_puts = plt_section_vaddr + 16 * 2; // PLT[2]
    int32_t rel32_puts_call  = (int32_t) (plt2_entry_vaddr_puts - (call_instruction_vaddr_puts + 8));

    *(int32_t *)(b->mem + text_section_off + 28) = rel32_puts_call ;

    *(int32_t *)(b->mem + plt_section_off + 32 + 2) = (int32_t)(
        (got_plt_section_vaddr + 4 * 8) - (plt_section_vaddr + 32 + 6)
    );

    *(int32_t *)(b->mem + plt_section_off + 16 * 3 -4) = (int32_t)(plt_section_vaddr - (plt_section_vaddr + 16 * 3)); // Corrected offset and value



    /**
     *    (gdb) b _start
     *    Breakpoint 1 at 0x401000
     *    (gdb) r
     *    Starting program: /mnt/f/C/simple_bytecode/lib/LibPEparse/cmake-build-debug/fixed_hello.elf
     *
     *    Breakpoint 1.2, 0x00007ffff7fe35c0 in _start () from /lib64/ld-linux-x86-64.so.2
     *    (gdb) c
     *    Continuing.
     *    Breakpoint 1.1, 0x0000000000401000 in _start ()
     *    (gdb) disas
     *    Dump of assembler code for function _start:
     *    => 0x0000000000401000 <+0>:     movabs $0x402000,%rdi
     *       0x000000000040100a <+10>:    xor    %eax,%eax
     *       0x000000000040100c <+12>:    call   0x401030 <printf@plt>
     *       0x0000000000401011 <+17>:    xor    %edi,%edi
     *       0x0000000000401013 <+19>:    mov    $0x3c,%eax
     *       0x0000000000401018 <+24>:    syscall
     *    End of assembler dump.
     *
     *
     * ┌──(desmon0xff㉿DESKTOP-N71RAHT)-[/mnt/f/C/simple_bytecode/lib/LibPEparse/cmake-build-debug]
     * └─$ objdump -M intel -d -j .plt fixed_hello.elf
     *
     * fixed_hello.elf:     file format elf64-x86-64
     *
     *
     * Disassembly of section .plt:
     *
     * 0000000000401020 <printf@plt-0x10>:
     *   401020:       ff 35 e2 1f 00 00       push   QWORD PTR [rip+0x1fe2]        # 403008 <printf@plt+0x1fd8>
     *   401026:       ff 25 e4 1f 00 00       jmp    QWORD PTR [rip+0x1fe4]        # 403010 <printf@plt+0x1fe0>
     *   40102c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]
     *
     * 0000000000401030 <printf@plt>:
     *   401030:       ff 25 da 1f 00 00       jmp    QWORD PTR [rip+0x1fda]        # 403010 <printf@plt+0x1fe0>
     *   401036:       68 00 00 00 00          push   0x0
     *   40103b:       e9 e0 ff ff ff          jmp    401020 <_start+0x20>
     *
     *
     * El "0x000000000040100c <+12>:    call   0x401030 <printf@plt>" del dbg, debe apuntar correctamente a la entrada
     * de la PLT que resuelve su simbolo "0000000000401030 <printf@plt>:" (en objdump)
     *
     */

    // --- Setup Program Headers ---
    // These directly modify the memory buffer where `b->phdr` points, which is right after the ELF header.

    // Segment 0: Executable segment (PT_LOAD, PF_R | PF_X)
    // Covers the ELF Header, Program Headers themselves, .text, and .plt.
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_X; // Read and Execute permissions
    phdr[0].p_offset = 0; // Starts from the beginning of the file
    phdr[0].p_vaddr = base_vaddr;
    phdr[0].p_paddr = base_vaddr;
    // File size covers up to the end of the .plt section, which marks the end of the RX content.
    phdr[0].p_filesz = rx_seg_file_end_offset;
    // Memory size should be page-aligned to cover the entire region in memory.
    phdr[0].p_memsz = (rx_seg_file_end_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    phdr[0].p_align = PAGE_SIZE;

    // Segment 1: Writable segment (PT_LOAD, PF_R | PF_W)
    // Covers .data, .got.plt, .dynamic, and any uninitialized data (BSS, though not used here).
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W; // Read and Write permissions
    // File offset starts at the page boundary where .data begins (after padding from RX segment).
    phdr[1].p_offset = (data_section_off / PAGE_SIZE) * PAGE_SIZE;
    phdr[1].p_vaddr = base_vaddr + phdr[1].p_offset; // Virtual address matches file offset relative to base_vaddr
    phdr[1].p_paddr = base_vaddr + phdr[1].p_offset;
    // File size covers from the segment's start offset to the end of the last included section (.dynamic).
    // Note: current_file_offset at this point holds the offset AFTER .dynamic, before .strtab/.symtab/.shstrtab
    phdr[1].p_filesz = current_file_offset - phdr[1].p_offset;
    phdr[1].p_memsz = phdr[1].p_filesz; // No BSS in this example, so memsz equals filesz
    phdr[1].p_align = PAGE_SIZE;

    // Segment 2: Program Interpreter segment (PT_INTERP)
    // Points to the dynamic linker (e.g., /lib64/ld-linux-x86-64.so.2).
    phdr[2].p_type = PT_INTERP;
    phdr[2].p_flags = PF_R; // Read-only
    phdr[2].p_offset = interp_section_off;
    phdr[2].p_vaddr = interp_section_vaddr;
    phdr[2].p_paddr = interp_section_vaddr;
    phdr[2].p_filesz = sizeof(interp); // Size of the interpreter path string including null terminator
    phdr[2].p_memsz = sizeof(interp);
    phdr[2].p_align = 1; // No specific alignment for interpreter path

    // Segment 3: Dynamic Linking Information segment (PT_DYNAMIC)
    // Points to the .dynamic section which contains metadata for dynamic linking.
    phdr[3].p_type = PT_DYNAMIC;
    phdr[3].p_flags = PF_R | PF_W; // Dynamic section is typically both readable and writable
    phdr[3].p_offset = dynamic_section_off;
    phdr[3].p_vaddr = dynamic_section_vaddr;
    phdr[3].p_paddr = dynamic_section_vaddr;
    phdr[3].p_filesz = sizeof(dynamic); // Size of the dynamic array
    phdr[3].p_memsz = sizeof(dynamic);
    phdr[3].p_align = 8; // Typically 8-byte aligned, sometimes 16


    // Finalize the ELF header and copy the section header table to the file.
    // The entry point is the virtual address of the .text section.
    elf_builder_finalize_exec64(b, text_section_vaddr);

    // --- Write the generated ELF file to disk ---
    FILE *f = fopen("fixed_hello.elf", "wb");
    if (!f) {
        perror("Error opening output file");
        elf_builder_free(b);
        return 1;
    }

    fwrite(b->mem, 1, b->size, f); // Write the entire ELF memory buffer
    fclose(f);

    printf("ELF executable generated: fixed_hello.elf (%zu bytes)\n", b->size);
    printf("To make it executable: chmod +x fixed_hello.elf\n");
    printf("Then run it: ./fixed_hello.elf\n");
    printf("If you see 'Hello world' printed to the console, it worked!\n");

    elf_builder_free(b); // Clean up allocated memory
    return 0;
}