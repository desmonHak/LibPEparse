#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

#define PAGE_SIZE 0x1000
int main() {
    // --- Código ensamblador: llama a printf a través de la PLT ---
    uint8_t code[] = {
        0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string>
        0x31, 0xc0,                   // xor eax, eax
        //0xe8, 0,0,0,0,                // call printf@plt (offset relleno después)
        0xe8, 0,0,0,0, // call <plt+16> (rellenar offset)
        /**
         * La instrucción call [RIP + offset] comienza en byte 14, luego de:
         * 0x48 0xbf  <8 bytes>   ; mov rdi, <string addr>
         * 0x31 0xc0              ; xor eax, eax
         *
         * La dirección RIP al momento de ejecución de esta instrucción será:
         * text_section_vaddr + 14 + 6 = instr_addr + 6
         *
         * Queremos que apunte a gotplt_addr + 16 (tercer slot, el que ld.so rellena con printf).
         */

        0x31, 0xff,                   // xor edi, edi
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
        0x0f, 0x05                    // syscall
    };



    const char hello_str[] = "Hola mundo\n";
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";
    const char dynstr[] = "\0printf\0libc.so.6\0";

    size_t code_size = sizeof(code);
    size_t data_size = sizeof(hello_str);
    uint64_t base_vaddr = 0x400000;
    size_t text_file_off = 0x1000;
    size_t data_file_off = text_file_off + 0x1000;
    size_t capacity = 16 * PAGE_SIZE;
    ElfBuilder *b = elf_builder_create_exec64(capacity);

    // .text
    if (text_file_off > b->size) {
        memset(b->mem + b->size, 0, text_file_off - b->size);
        b->size = text_file_off;
    }
    size_t text_section_off; uint64_t text_section_vaddr;
    elf_builder_add_section_ex(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        code, code_size, base_vaddr + text_file_off, 16,
        &text_section_off, &text_section_vaddr, 0, 0, 0
    );

    // .plt (PLT0 + PLT1)
    // PLT0: estándar x86-64
    // PLT1: salto indirecto a GOT
    uint8_t plt_code[] = {
        // PLT0
        0xff, 0x35, 0,0,0,0,             // push QWORD PTR [rip+X] (got+8)
        0xff, 0x25, 0,0,0,0,             // jmp  QWORD PTR [rip+Y] (got+16)
        0x0f, 0x1f, 0x40, 0x00,          // nop dword ptr [rax+0x0]
        // PLT1 (printf)
        0xff, 0x25, 0,0,0,0,             // jmp QWORD PTR [rip+Z] (got+24)
        0x68, 0x00,0x00,0x00,0x00,       // pushq <reloc index>
        0xe9, 0,0,0,0                    // jmp .plt[0]
    };
    // Los offsets rip-relativos se rellenan después
    size_t plt_off = b->size;
    size_t plt_vaddr = base_vaddr + plt_off;
    elf_builder_add_section_ex(
        b, ".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        plt_code, sizeof(plt_code), plt_vaddr, 16, NULL, NULL, 0, 0, 0
    );

    // .data
    if (data_file_off > b->size) {
        memset(b->mem + b->size, 0, data_file_off - b->size);
        b->size = data_file_off;
    }
    size_t data_section_off; uint64_t data_section_vaddr;
    elf_builder_add_section_ex(
        b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
        hello_str, data_size, base_vaddr + data_file_off, 8,
        &data_section_off, &data_section_vaddr, 0, 0, 0
    );

    // Parchea dirección del string en el código
    *(uint64_t *)(b->mem + text_section_off + 2) = data_section_vaddr;

    // .interp
    size_t interp_off = b->size;
    memcpy(b->mem + interp_off, interp, sizeof(interp));
    b->size += sizeof(interp);
    size_t idx_interp = elf_builder_add_section_ex(
        b, ".interp", SHT_PROGBITS, SHF_ALLOC, b->mem + interp_off, sizeof(interp),
        base_vaddr + interp_off, 1, NULL, NULL, 0, 0, 0
    );

    // .dynstr
    size_t dynstr_off = b->size;
    size_t dynstr_size = sizeof(dynstr);
    memcpy(b->mem + dynstr_off, dynstr, dynstr_size);
    b->size += dynstr_size;
    size_t idx_dynstr = elf_builder_add_section_ex(
        b, ".dynstr", SHT_STRTAB, SHF_ALLOC, b->mem + dynstr_off, dynstr_size,
        base_vaddr + dynstr_off, 1, NULL, NULL, 0, 0, 0
    );

    // .dynsym
    Elf64_Sym dynsym[2] = {0};
    dynsym[0].st_name = 0; // símbolo nulo
    dynsym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    dynsym[0].st_shndx = SHN_UNDEF;
    dynsym[1].st_name = 1; // offset en dynstr: "printf"
    dynsym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    dynsym[1].st_shndx = SHN_UNDEF;
    dynsym[1].st_value = 0;
    dynsym[1].st_size = 0;
    size_t dynsym_off = b->size;
    memcpy(b->mem + dynsym_off, dynsym, sizeof(dynsym));
    b->size += sizeof(dynsym);
    size_t idx_dynsym = elf_builder_add_section_ex(
        b, ".dynsym", SHT_DYNSYM, SHF_ALLOC, b->mem + dynsym_off, sizeof(dynsym),
        base_vaddr + dynsym_off, 8, NULL, NULL, idx_dynstr, 1, sizeof(Elf64_Sym)
    );

    // .got.plt (mínimo: 3 entradas: 0, link_map, printf@got)
    uint64_t got_plt[3] = {0};
    size_t got_plt_off = b->size;
    memcpy(b->mem + got_plt_off, got_plt, sizeof(got_plt));
    b->size += sizeof(got_plt);
    size_t idx_gotplt = elf_builder_add_section_ex(
        b, ".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, b->mem + got_plt_off, sizeof(got_plt),
        base_vaddr + got_plt_off, 8, NULL, NULL, 0, 0, 0
    );

    // .rela.plt: relocation sobre got_plt[2] (printf@got)
    Elf64_Rela rela = {0};
    rela.r_offset = base_vaddr + got_plt_off + 2 * 8; // got_plt[2]
    rela.r_info = ELF64_R_INFO(1, R_X86_64_JUMP_SLOT); // símbolo 1: printf
    rela.r_addend = 0;
    size_t rela_plt_off = b->size;
    memcpy(b->mem + rela_plt_off, &rela, sizeof(rela));
    b->size += sizeof(rela);
    size_t idx_relaplt = elf_builder_add_section_ex(
        b, ".rela.plt", SHT_RELA, SHF_ALLOC, b->mem + rela_plt_off, sizeof(rela),
        base_vaddr + rela_plt_off, 8, NULL, NULL, idx_dynsym, idx_gotplt, sizeof(Elf64_Rela)
    );

    // .dynamic
    Elf64_Dyn dynamic[] = {
        {DT_NEEDED, {8}}, // "libc.so.6" al final de dynstr
        {DT_STRTAB, {base_vaddr + dynstr_off}},
        {DT_SYMTAB, {base_vaddr + dynsym_off}},
        {DT_RELA,   {base_vaddr + rela_plt_off}},
        {DT_RELASZ, {sizeof(rela)}},
        {DT_RELAENT, {sizeof(Elf64_Rela)}},
        {DT_STRSZ, {dynstr_size}},
        {DT_SYMENT, {sizeof(Elf64_Sym)}},
        {DT_PLTGOT, {base_vaddr + got_plt_off}},
        {DT_PLTRELSZ, {sizeof(rela)}},
        {DT_PLTREL, {DT_RELA}},
        {DT_JMPREL, {base_vaddr + rela_plt_off}},
        {DT_NULL, {0}}
    };
    size_t dynamic_off = b->size;
    memcpy(b->mem + dynamic_off, dynamic, sizeof(dynamic));
    b->size += sizeof(dynamic);
    size_t idx_dynamic = elf_builder_add_section_ex(
        b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
        b->mem + dynamic_off, sizeof(dynamic), base_vaddr + dynamic_off, 8, NULL, NULL, idx_dynstr, 0, sizeof(Elf64_Dyn)
    );

    // --- .strtab (tabla de strings para .symtab) ---
    const char strtab[] = "\0_start\0";
    size_t strtab_off = b->size;
    memcpy(b->mem + strtab_off, strtab, sizeof(strtab));
    b->size += sizeof(strtab);
    size_t idx_strtab = elf_builder_add_section_ex(
        b, ".strtab", SHT_STRTAB, 0, b->mem + strtab_off, sizeof(strtab),
        0, 1, NULL, NULL, 0, 0, 0
    );
    
    // --- .symtab (símbolo _start) ---
    Elf64_Sym symtab[2] = {0};
    symtab[0].st_name = 0; // símbolo nulo
    symtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    symtab[0].st_shndx = SHN_UNDEF;
    symtab[1].st_name = 1; // offset en strtab: "_start"
    symtab[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symtab[1].st_shndx = 1; // sección .text
    symtab[1].st_value = text_section_vaddr;
    symtab[1].st_size = code_size;
    size_t symtab_off = b->size;
    memcpy(b->mem + symtab_off, symtab, sizeof(symtab));
    b->size += sizeof(symtab);
    size_t idx_symtab = elf_builder_add_section_ex(
        b, ".symtab", SHT_SYMTAB, 0, b->mem + symtab_off, sizeof(symtab),
        0, 8, NULL, NULL, idx_strtab, 1, sizeof(Elf64_Sym)
    );


    // .shstrtab
    size_t shstrtab_off = b->size;
    memcpy(b->mem + shstrtab_off, b->shstrtab, b->shstrtab_len);
    b->size += b->shstrtab_len;
    size_t idx_shstrtab = elf_builder_add_section_ex(
        b, ".shstrtab", SHT_STRTAB, 0, b->mem + shstrtab_off, b->shstrtab_len, 0, 1, NULL, NULL, 0, 0, 0
    );
    b->shstrndx = idx_shstrtab;

    // --- Parcheos finales ---
    // Parchea el call (offset relativo a RIP) en .text
    uint64_t call_addr = text_section_vaddr + 14;
    uint64_t plt1_addr = plt_vaddr + 16; // PLT1 offset
    int32_t rel32 = (int32_t)(plt1_addr - (call_addr + 4));
    *(uint32_t *)(b->mem + text_section_off + 14) = rel32;

    // Parchea PLT0 y PLT1 offsets
    uint64_t gotplt_addr = base_vaddr + got_plt_off;
    // PLT0: push [rip+X], jmp [rip+Y]
    uint32_t off_got8  = (uint32_t)(gotplt_addr + 8  - (plt_vaddr + 6));  // [rip+off] para push
    uint32_t off_got16 = (uint32_t)(gotplt_addr + 16 - (plt_vaddr + 12)); // [rip+off] para jmp
    *(uint32_t *)(b->mem + plt_off + 2)  = off_got8;
    *(uint32_t *)(b->mem + plt_off + 8)  = off_got16;
    // PLT1: jmp [rip+Z]
    uint32_t off_got24 = (uint32_t)(gotplt_addr + 16 - (plt_vaddr + 20)); // [rip+off] para jmp
    *(uint32_t *)(b->mem + plt_off + 18) = off_got24;
    // pushq reloc index (0)
    *(uint32_t *)(b->mem + plt_off + 24) = 0;
    // jmp .plt[0]
    int32_t plt0_disp = (int32_t)(plt_vaddr - (plt_vaddr + 28 + 4));
    *(int32_t *)(b->mem + plt_off + 28) = plt0_disp;

    // --- Finalizar ELF: tabla de secciones y headers ---
    if (b->size % 8 != 0) b->size = (b->size + 7) & ~7;
    size_t shdr_offset = b->size;
    memcpy(b->mem + shdr_offset, b->shdr, b->shnum * sizeof(Elf64_Shdr));
    b->size += b->shnum * sizeof(Elf64_Shdr);

    // ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)b->ehdr;
    memset(ehdr, 0, sizeof(*ehdr));
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr->e_ident[EI_ABIVERSION] = 0;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = text_section_vaddr;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_shoff = shdr_offset;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 4;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_shnum = b->shnum;
    ehdr->e_shstrndx = b->shstrndx;

    // Program headers
    Elf64_Phdr *phdr = (Elf64_Phdr *)(b->mem + sizeof(Elf64_Ehdr));
    // RX segment (.text + .plt)
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_offset = text_section_off;
    phdr[0].p_vaddr = text_section_vaddr;
    phdr[0].p_paddr = text_section_vaddr;
    phdr[0].p_filesz = plt_off + sizeof(plt_code) - text_section_off;
    phdr[0].p_memsz = plt_off + sizeof(plt_code) - text_section_off;
    phdr[0].p_flags = PF_X | PF_R;
    phdr[0].p_align = PAGE_SIZE;
    // RW segment (.data + dinámicas)
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_offset = data_section_off;
    phdr[1].p_vaddr = data_section_vaddr;
    phdr[1].p_paddr = data_section_vaddr;
    phdr[1].p_filesz = b->size - data_section_off;
    phdr[1].p_memsz = b->size - data_section_off;
    phdr[1].p_flags = PF_W | PF_R;
    phdr[1].p_align = PAGE_SIZE;

    // PT_INTERP: segment para el intérprete dinámico
    phdr[2].p_type = PT_INTERP;
    phdr[2].p_offset = interp_off;
    phdr[2].p_vaddr = base_vaddr + interp_off;
    phdr[2].p_paddr = base_vaddr + interp_off;
    phdr[2].p_filesz = sizeof(interp);
    phdr[2].p_memsz = sizeof(interp);
    phdr[2].p_flags = PF_R;
    phdr[2].p_align = 1;

    // PT_DYNAMIC: necesario para enlazado dinámico en tiempo de ejecución
    phdr[3].p_type = PT_DYNAMIC;
    phdr[3].p_offset = dynamic_off;
    phdr[3].p_vaddr = base_vaddr + dynamic_off;
    phdr[3].p_paddr = base_vaddr + dynamic_off;
    phdr[3].p_filesz = sizeof(dynamic);
    phdr[3].p_memsz = sizeof(dynamic);
    phdr[3].p_flags = PF_R | PF_W;
    phdr[3].p_align = 8;




    FILE *f = fopen("salida_printf.elf", "wb");
    if (!f) { perror("Error al abrir el archivo de salida"); elf_builder_free(b); return 1; }
    fwrite(b->mem, 1, b->size, f);
    fclose(f);
    printf("ELF ejecutable generado: salida_printf.elf (%zu bytes)\n", b->size);
    printf("Para hacerlo ejecutable: chmod +x salida_printf.elf\n");
    printf("Si al ejecutar ves 'Hola mundo', funciono\n");
    elf_builder_free(b);
    return 0;
}
