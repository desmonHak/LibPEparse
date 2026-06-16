#ifndef CREATE_ELF_C
#define CREATE_ELF_C

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h> // For fprintf, etc., for error reporting

#include "CreateELF.h"
#include "LibELFparse.h"
// Define initial section header table capacity
#define INITIAL_SHDR_CAPACITY 16

// Initializes a new ElfBuilder for a 64-bit executable.
// Allocates main memory buffer and temporary section header/string table buffers.
ElfBuilder *elf_builder_create_exec64(size_t capacity, size_t number_program_headers) {
    // Allocate the main ElfBuilder structure
    ElfBuilder *b = calloc(1, sizeof(ElfBuilder));
    if (!b) {
        fprintf(stderr, "Error: Failed to allocate ElfBuilder structure.\n");
        return NULL;
    }

    // Allocate the main memory buffer that will hold the entire ELF file content.
    // `calloc` ensures this memory is initialized to zeros.
    b->mem = calloc(1, capacity);
    if (!b->mem) {
        fprintf(stderr, "Error: Failed to allocate main ELF memory buffer.\n");
        free(b);
        return NULL;
    }

    b->capacity = capacity;
    b->size = 0; // Current size of data in the buffer
    b->is64 = 1; // Mark as 64-bit ELF

    // Initialize shstrtab (section header string table) buffer.
    // It starts with a mandatory null byte at offset 0.
    b->shstrtab_cap = 256; // Initial capacity
    b->shstrtab = calloc(1, b->shstrtab_cap);
    if (!b->shstrtab) {
        fprintf(stderr, "Error: Failed to allocate shstrtab buffer.\n");
        free(b->mem);
        free(b);
        return NULL;
    }
    b->shstrtab_len = 1; // First byte is always null

    // Reserve space for ELF header and program headers at the beginning of the memory buffer.
    // The ELF header (Elf64_Ehdr) comes first.
    b->ehdr = b->mem;
    b->size = sizeof(Elf64_Ehdr);

    // Program headers (Elf64_Phdr) immediately follow the ELF header.
    b->phdr = b->mem + b->size;

    // example: 2 PT_LOAD, 1 PT_INTERP, 1 PT_DYNAMIC, 1 NULL (for alignment/placeholder)
    b->phnum = number_program_headers;
    b->size += b->phnum * sizeof(Elf64_Phdr); // Increase buffer size to account for program headers

    // Initialize the temporary section header table.
    // This table is built up in a separate buffer (`shdr_temp`) and copied to `b->mem` later during finalization.
    b->shdr_temp = calloc(INITIAL_SHDR_CAPACITY, sizeof(Elf64_Shdr));
    if (!b->shdr_temp) {
        fprintf(stderr, "Error: Failed to allocate temporary section header table.\n");
        free(b->shstrtab);
        free(b->mem);
        free(b);
        return NULL;
    }

    // Initialize with a NULL section (mandatory first section, index 0).
    // shnum tracks the number of actual sections added (starting from 1 for SHT_NULL).
    b->shnum = 1; // Section 0 is always SHT_NULL
    // shstrndx will be updated later to point to the actual .shstrtab section index.
    b->shstrndx = 0;

    return b;
}

// Helper function to resize the temporary section header table (b->shdr_temp) if needed.
static int resize_shdr_temp(ElfBuilder *b) {
    // Double the current number of sections to determine new capacity.
    size_t new_cap = b->shnum * 2;
    // Ensure new capacity is at least double the initial capacity if it's currently very small.
    if (new_cap < INITIAL_SHDR_CAPACITY) new_cap = INITIAL_SHDR_CAPACITY * 2;

    void *new_shdr = realloc(b->shdr_temp, new_cap * sizeof(Elf64_Shdr));
    if (!new_shdr) {
        fprintf(stderr, "Error: Failed to reallocate temporary section header table.\n");
        return 0; // Failed to reallocate
    }
    b->shdr_temp = new_shdr;
    // Initialize newly allocated memory to zero to prevent garbage values.
    memset((uint8_t*)b->shdr_temp + b->shnum * sizeof(Elf64_Shdr), 0, (new_cap - b->shnum) * sizeof(Elf64_Shdr));
    return 1;
}

// Adds a section to the ELF file being built.
// `name`: Name of the section (e.g., ".text", ".data").
// `type`: Section type (e.g., SHT_PROGBITS, SHT_DYNSYM).
// `flags`: Section flags (e.g., SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE).
// `data`: Pointer to the raw data for the section. Can be NULL for SHT_NOBITS.
// `size`: Size of the raw data.
// `vaddr`: Virtual address where this section will be loaded (0 if not allocatable).
// `align`: Required alignment for the section's data.
// `out_offset`: Optional output for the section's file offset.
// `out_vaddr`: Optional output for the section's virtual address.
// `sh_link`, `sh_info`, `sh_entsize`: Extended fields for certain section types (e.g., symbol tables).
size_t elf_builder_add_section_ex(
    ElfBuilder *b,
    const char *name,
    uint32_t type,
    uint64_t flags,
    const void *data,
    size_t size,
    uint64_t vaddr,
    uint64_t align,
    size_t *out_offset,
    uint64_t *out_vaddr,
    uint32_t sh_link,
    uint32_t sh_info,
    uint64_t sh_entsize
) {
    // Check if temporary section header table needs resizing before adding a new entry.
    // `b->shnum` is the *next* available index, so if it equals current capacity, we need to resize.
    if (b->shnum >= INITIAL_SHDR_CAPACITY && !resize_shdr_temp(b)) {
        fprintf(stderr, "Error: Temporary section header table is full and cannot be resized.\n");
        return 0; // Return 0 to indicate failure
    }

    // Align the current file offset (b->size) based on the provided alignment.
    // This ensures the section data starts at the correct aligned boundary in the file.
    size_t align_mask = align ? align - 1 : 0;
    if (align && (b->size & align_mask)) {
        printf("alineando seccion %s a %llu\n", name, align);
        b->size = (b->size + align_mask) & ~align_mask;
    }
    size_t file_off = b->size; // This is the file offset where the section data will start

    // Align the virtual address based on the provided alignment.
    // This ensures the section maps to memory at the correct aligned virtual address.
    uint64_t va = vaddr;
    if (align && (va & align_mask)) {
        va = (va + align_mask) & ~align_mask;
    }

    // Copy the section name to the section header string table (b->shstrtab).
    size_t name_off = b->shstrtab_len; // Offset of the name within shstrtab
    size_t namelen = strlen(name) + 1; // Include null terminator

    // Resize shstrtab buffer if current capacity is insufficient.
    if (b->shstrtab_len + namelen > b->shstrtab_cap) {
        size_t new_cap = b->shstrtab_cap * 2;
        char *new_strtab = realloc(b->shstrtab, new_cap);
        if (!new_strtab) {
            fprintf(stderr, "Error: Failed to resize shstrtab buffer for section name '%s'.\n", name);
            return 0;
        }
        b->shstrtab = new_strtab;
        b->shstrtab_cap = new_cap;
    }
    memcpy(b->shstrtab + b->shstrtab_len, name, namelen);
    b->shstrtab_len += namelen;

    // Copy section data to the main ELF memory buffer (`b->mem`).
    // For SHT_NOBITS sections (like .bss), data is not copied, but size is still accounted for.
    if (data && size > 0) {
        // Ensure enough capacity in main memory buffer before copying data.
        if (file_off + size > b->capacity) {
            fprintf(stderr, "Error: Not enough capacity in main ELF memory buffer for section data '%s'.\n", name);
            return 0;
        }
        memcpy(b->mem + file_off, data, size);
        b->size = file_off + size; // Update `b->size` to reflect the new end of file data
    } else if (type != SHT_NOBITS) { // For SHT_NOBITS, size increases but no data is copied from source
        b->size = file_off + size;
    }


    // Fill the section descriptor in the temporary section header table.
    Elf64_Shdr *shdr_array = (Elf64_Shdr *)b->shdr_temp;
    Elf64_Shdr *s = &shdr_array[b->shnum]; // Get pointer to the next available section header entry
    memset(s, 0, sizeof(*s)); // Clear the entry to ensure all fields are zeroed initially

    s->sh_name = name_off;       // Offset of section name in .shstrtab
    s->sh_type = type;           // Type of section
    s->sh_flags = flags;         // Attributes (e.g., writable, executable, allocatable)
    s->sh_addr = va;             // Virtual address (0 if not allocatable)
    s->sh_offset = file_off;     // Offset of section data in the file
    s->sh_size = size;           // Size of section data in file/memory
    s->sh_addralign = align ? align : 1; // Required alignment, default to 1-byte
    s->sh_link = sh_link;       // Link to another section (e.g., symbol table links to string table)
    s->sh_info = sh_info;       // Additional info (e.g., first non-local symbol index for SYMTAB)
    s->sh_entsize = sh_entsize; // Size of each entry if section holds a table (e.g., Elf64_Sym for SYMTAB)

    // Output the file offset and virtual address if requested by the caller.
    if (out_offset) *out_offset = file_off;
    if (out_vaddr)  *out_vaddr = va;

    return b->shnum++; // Increment section count and return the index of the newly added section
}

// Wrapper for the simpler add_section (uses default values for extended fields).
size_t elf_builder_add_section(ElfBuilder *b, const char *name, uint32_t type, uint64_t flags,
                               const void *data, size_t size, uint64_t vaddr, uint64_t align,
                               size_t *out_offset, uint64_t *out_vaddr) {
    return elf_builder_add_section_ex(b, name, type, flags, data, size, vaddr, align,
                                      out_offset, out_vaddr, 0, 0, 0); // Default sh_link, sh_info, sh_entsize to 0
}


// Finalizes the ELF executable by populating the ELF header and copying the section header table.
// The program headers are expected to be set up by the caller directly in b->phdr.
void elf_builder_finalize_exec64(ElfBuilder *b, uint64_t entry) {
    // --- Add the .shstrtab section (section names string table) ---
    // This section contains the names of all other sections. It's usually placed near the end of the file.

    // First, add the ".shstrtab" name itself to the shstrtab buffer.
    size_t shstrtab_name_in_strtab_off = b->shstrtab_len;
    const char *shstrtab_name_str = ".shstrtab";
    size_t shstrtab_name_str_len = strlen(shstrtab_name_str) + 1;

    // Ensure capacity for the string ".shstrtab" in shstrtab buffer itself.
    if (b->shstrtab_len + shstrtab_name_str_len > b->shstrtab_cap) {
        size_t new_cap = b->shstrtab_cap * 2;
        char *new_strtab = realloc(b->shstrtab, new_cap);
        if (!new_strtab) {
            fprintf(stderr, "Error: Failed to resize shstrtab for its own name.\n");
            return;
        }
        b->shstrtab = new_strtab;
        b->shstrtab_cap = new_cap;
    }
    memcpy(b->shstrtab + b->shstrtab_len, shstrtab_name_str, shstrtab_name_str_len);
    b->shstrtab_len += shstrtab_name_str_len;


    // Align the file offset where the .shstrtab content will be placed.
    // Generally, .shstrtab does not require strict alignment for its data in the file, but 4-byte is common.
    if (b->size % 4 != 0) {
        b->size = (b->size + 3) & ~3;
    }

    // Copy the actual content of the shstrtab buffer to the ELF file memory (`b->mem`).
    size_t shstrtab_content_file_off = b->size;
    // Ensure enough capacity in main memory buffer for shstrtab content.
    if (shstrtab_content_file_off + b->shstrtab_len > b->capacity) {
        fprintf(stderr, "Error: Not enough capacity in ELF memory buffer for .shstrtab content.\n");
        return;
    }
    memcpy(b->mem + shstrtab_content_file_off, b->shstrtab, b->shstrtab_len);
    b->size += b->shstrtab_len;

    // Add the section descriptor for .shstrtab to the temporary shdr array (`b->shdr_temp`).
    // Check if temporary section header table needs resizing for .shstrtab entry.
    if (b->shnum >= INITIAL_SHDR_CAPACITY && !resize_shdr_temp(b)) {
        fprintf(stderr, "Error: Failed to resize section header table for .shstrtab entry.\n");
        return;
    }
    Elf64_Shdr *shdr_array = (Elf64_Shdr *)b->shdr_temp;
    Elf64_Shdr *shstrtab_shdr = &shdr_array[b->shnum];
    memset(shstrtab_shdr, 0, sizeof(*shstrtab_shdr)); // Clear the entry
    shstrtab_shdr->sh_name = shstrtab_name_in_strtab_off; // Offset of ".shstrtab" name in shstrtab
    shstrtab_shdr->sh_type = SHT_STRTAB;
    shstrtab_shdr->sh_flags = 0; // String tables typically don't have alloc/write flags
    shstrtab_shdr->sh_addr = 0; // No virtual address for string table contents
    shstrtab_shdr->sh_offset = shstrtab_content_file_off;
    shstrtab_shdr->sh_size = b->shstrtab_len;
    shstrtab_shdr->sh_addralign = 1; // 1-byte alignment

    b->shstrndx = b->shnum; // Mark this section's index as the section header string table index
    b->shnum++; // Increment section count


    // --- Copy the temporary section header table to the end of the ELF file memory (`b->mem`) ---
    // Align the offset for the final Section Header Table (SHT).
    // For 64-bit ELF, 8-byte alignment for the SHT is typical.
    if (b->size % 8 != 0) {
        b->size = (b->size + 7) & ~7;
    }

    size_t final_shdr_offset = b->size;
    // Ensure enough capacity in main memory buffer for final SHT.
    if (final_shdr_offset + b->shnum * sizeof(Elf64_Shdr) > b->capacity) {
        fprintf(stderr, "Error: Not enough capacity in ELF memory buffer for final section header table.\n");
        return;
    }
    memcpy(b->mem + final_shdr_offset, b->shdr_temp, b->shnum * sizeof(Elf64_Shdr));
    b->size += b->shnum * sizeof(Elf64_Shdr);


    // --- Configure the ELF header ---
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)b->ehdr; // `ehdr` points to the beginning of `b->mem`
    memset(ehdr, 0, sizeof(Elf64_Ehdr)); // Clear it to ensure all fields are set correctly

    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;      // 64-bit ELF
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;      // Little-endian
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;    // Current ELF version
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;   // Standard System V ABI
    ehdr->e_ident[EI_ABIVERSION] = 0;          // No specific ABI version
    ehdr->e_type = ET_EXEC;                    // Executable file
    ehdr->e_machine = EM_X86_64;               // x86-64 architecture
    ehdr->e_version = EV_CURRENT;              // ELF current version
    ehdr->e_entry = entry;                     // Entry point virtual address (provided by caller)
    ehdr->e_phoff = sizeof(Elf64_Ehdr);        // Program headers are located right after the ELF header
    ehdr->e_shoff = final_shdr_offset;         // Section header table is at the end of the file
    ehdr->e_flags = 0;                         // No specific flags for x86-64
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);       // Size of ELF header
    ehdr->e_phentsize = sizeof(Elf64_Phdr);    // Size of program header entry
    ehdr->e_phnum = b->phnum;                  // Number of program header entries (set in `create_exec64`)
    ehdr->e_shentsize = sizeof(Elf64_Shdr);    // Size of section header entry
    ehdr->e_shnum = b->shnum;                  // Number of section header entries
    ehdr->e_shstrndx = b->shstrndx;            // Index of section name string table
}

// Frees all memory allocated by the ElfBuilder.
void elf_builder_free(ElfBuilder *b) {
    if (b) {
        free(b->mem);       // Free the main ELF memory buffer
        free(b->shstrtab);  // Free the section name string table buffer
        free(b->shdr_temp); // Free the temporary section header array
        free(b);            // Free the ElfBuilder structure itself
    }
}

/**
 * Permite crear una tabla PLT con la cantidad de entradas especificadas, cada entrada
 * sera una "plt_entry_t", el cual ocupara 16 bytes.
 * La primera entrada, de una PLT es especial y no deberia ser usada como el resto,
 * la primera entrada permite la resolucion de los simbolos descritos en las siguientes entradas.
 *
 * Es necesario liberar la memoria usando free
 *
 * @param number_entry cantidad de entradas a reserbar.
 * @return tabla con todas las entradas inicializadas
 */
plt_entry_t* init_plt_table(size_t number_entry) {
    if (number_entry == 0) return NULL;
    plt_entry_t *plt_code = calloc(sizeof(plt_entry_t), number_entry);

    size_t counter = 0;
    plt_code[0] = (plt_entry_t){ // la primera entrada es especial y tien codigo distinto al resto
        .raw = {
            // push QWORD PTR [rip+GOT[1]]: Apila link_map (puntero a metadatos)
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00,

            // jmp QWORD PTR [rip+GOT[2]]: Salta a _dl_runtime_resolve (resolución dinámica)
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00,

            0x0f, 0x1f, 0x40, 0x00, // nop padding para alineación de 16 bytes
        }
    };
    counter += 1; // avanzar a la siguiente PLT

    // codigo por defecto para cada entrada de la tabla de la PLT
    const plt_entry_t plt_code_base_entry = {
        // jmp QWORD PTR [rip+GOT_printf_offset]: Salto inicial (sin resolver) a la GOT
        .jmp_got    = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00},
        .push       = {0x68, 0x00, 0x00, 0x00, 0x00},   // pushq indice: Índice de la funcion
        .jmp_plt    = {0xe9, 0x00, 0x00, 0x00, 0x00}    // jmp PLT0: Inicia resolución
    };

    // copiar el contenido por defecto de una PLT a cada entrada
    for (; counter < number_entry; ++counter) {
        memcpy(&(plt_code[counter]), &plt_code_base_entry, sizeof(plt_entry_t));
    }
    return plt_code;
}

/**
 * Convierte un array de tipo ImportLibrary, en su represantacion de tipo cadena
 * @param libs_with_funcs array de librerias con las funciones asociadas de la que generar una
 * cadena con todas estas contenidas.
 * @param number_libs numero de librerias, equivalente al tamaño de "libs_with_funcs"
 * @param size_output tamaño de la cadena de salida
 * @return Una cadena unica separa por terminadores nulos, que se necesita para "dynstr":
 * "\0printf\0libc.so.6\0"
 */
char* join_string_libs_func(ImportLibrary* libs_with_funcs, size_t number_libs, size_t* size_output) {

    // tamaño del string final
    size_t size_dynstr = 1;

    // bucle para calcular el tamaño total de la cadena final
    for (size_t index_lib = 0; index_lib < number_libs; index_lib++) {
        // calcular la longitud del string de la libreria, mas el caracter nulo
        size_dynstr += strlen(libs_with_funcs[index_lib].dllName) + 1;
        for (size_t j = 0; j < libs_with_funcs[index_lib].numFunctions; j++) {
            // sumar la longitud de cada string mas terminador nulo
            size_dynstr += strlen(libs_with_funcs[index_lib].functions[j]) + 1;
        }
    }

    // reservar memoria e inicializar con 0
    char* dynstr = calloc(size_dynstr, 1);
    if (!dynstr) return NULL;

    // rellenar el string
    size_t offset = 1; // empezamos desde el índice 1, dejando el primer '\0'
    for (size_t i = 0; i < number_libs; i++) {
        ImportLibrary* lib = &libs_with_funcs[i];

        for (size_t j = 0; j < lib->numFunctions; j++) {
            const char* func = lib->functions[j];
            size_t len = strlen(func);
            memcpy(&dynstr[offset], func, len);
            offset += len + 1; // mover después del '\0'
        }

        const char* dll = lib->dllName;
        size_t len = strlen(dll);
        memcpy(&dynstr[offset], dll, len);
        offset += len + 1;
    }

    *size_output = size_dynstr;
    return dynstr;

}

void print_dynstr(const char* dynstr, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (dynstr[i] == '\0') {
            printf("\\0");
        } else {
            putchar(dynstr[i]);
        }
    }
    putchar('\n');
}

/**
 * Permite buscar el offset donde empieza una cadena dada, buscando en un string como
 * "\0printf\0puts\0libc.so.6\0"
 * @param dynstr cadena de tipo "\0printf\0puts\0libc.so.6\0" en la que buscar
 * @param target cadena a buscar, por ejemplo "printf"
 * @return offset donde inicia la cadena
 */
size_t dynstr_find_offset(const char* dynstr, const char* target) {
    size_t offset = 0;

    while (dynstr[offset] != '\0' || offset == 0) {
        // Compara el nombre actual con el objetivo
        if (strcmp(&dynstr[offset], target) == 0) {
            return offset;
        }

        // Avanza al siguiente string
        offset += strlen(&dynstr[offset]) + 1;
    }

    // No encontrado
    return (size_t)-1;
}

void init_plt0(
    plt_entry_t *plt,
    uint64_t plt_section_vaddr,
    uint64_t got_plt_section_vaddr
) {
    /**
     * Debemos calcular el desplazamiento entre la segunda entrada de la GOT(GOT[1]) y la instruccion
     * push QWORD PTR [rip+GOT[1]_offset]", la primera entrada de la GOT contiene el "link_map" necesario
     * para llamar al linker
     * :
     *         // PLT0 (Offset 0 in .plt section, used for dynamic linker setup)
     *         // push QWORD PTR [rip+GOT[1]_offset]
     *         // This pushes the link_map pointer (GOT[1]) onto the stack.
     *         0xff, 0x35, 0,0,0,0,
     *         // jmp QWORD PTR [rip+GOT[2]_offset]
     *         // This jumps to the _dl_runtime_resolve function provided by the dynamic linker (GOT[2]).
     *         0xff, 0x25, 0,0,0,0,
     *         0x0f, 0x1f, 0x40, 0x00,          // nop dword ptr [rax+0x0] (padding for 16-byte alignment)
     *
     * Para acceder a la segunda entrada de la GOT, se debe multiplicar 8(tamaño de cada entrada) por el indice
     * al que queremos acceder "1" y sumar esto a la direccion base VIRTUAL de la GOT:
     *          got_plt_section_vaddr + 8 * 1 == GET_GOT_ENTRY_ADDR(got_plt_section_vaddr, 1)
     * Luego debermos acceder a la instruccion PUTS de la PLT[0], la cual ocupa 6 bytes la instruccion, por lo que lo
     * sumaremos a la direccion base de la PLT(PLT[0]) y restaremos las direcciones ya descritas, obteniendo una
     * diferencia el cual corresponde al offset que el push necesita
     */
    plt[0].offset_jmp_got = (int32_t)(GET_GOT_ENTRY_ADDR(got_plt_section_vaddr, 1) - (plt_section_vaddr + 6));

    // PLT0: `jmp  QWORD PTR [rip+Y]` (points to GOT+16, i.e., GOT[2])
    // Instruction `0xff, 0x25` is at `plt_section_off + 6`. It's 6 bytes long.
    // `RIP` will be `plt_section_vaddr + 6 + 6 = plt_section_vaddr + 12`. Target is `got_plt_section_vaddr + 16`.
    *(int32_t *)((void*)&plt + 8) = (int32_t)(GET_GOT_ENTRY_ADDR(got_plt_section_vaddr, 2) - (plt_section_vaddr + 12));

}

/**
 * Permite parchear una instruccion que debe apuntar a una direccion de la PLT para
 * llamar a alguna funcion de alguna libreria externa.
 *
 * @param plt PLT que modificar, debe ser un buffer de 16 bytes * numero_entradas_PLT.
 * @param plt_index indice de la entrada PLT que parchear para que apunte a la GOT indicada
 * y PLT que usar parchear la instruccion del codigo real.
 * @param text_section seccion de texto desplazada al inicio de la instruccion que desea modificar.
 * @param plt_section_vaddr direccion virtual incial de la seccion PLT.
 * @param got_plt_section_vaddr direccion virtual incial de la GOT.
 * @param got_plt_index indice de la GOT que usar, los indices 0, 1 y 2 estan reservados para el linker.
 * @param text_section_vaddr direccion virtual desplazada con el offset de la isntruccion a modificar.
 * @param index_func indice de la funcion que ocupara este espacio.
 * @param offset_path_instruction offset de la instruccion desde la que modificar la instruccion, por ejemplo
 * para un "0xFF, 0x15, 0x00, 0x00, 0x00, 0x00" // call [RIP+disp32] el offset empieza apartir de
 * "0xFF, 0x15", que son 2 bytes.
 * @param sizeof_instruction tamaño de la instruccion completa a modificar.
 */
void resolve_and_patch_got_plt(
    plt_entry_t *plt,
    size_t plt_index,
    void *text_section,
    uint64_t plt_section_vaddr,
    uint64_t got_plt_section_vaddr,
    uint32_t got_plt_index,
    uint64_t text_section_vaddr,
    uint32_t index_func,
    size_t offset_path_instruction,
    size_t sizeof_instruction
) {
    printf("[*] Debug Info:\n");
    printf("    plt:                  0x%p\n", (void *)plt);
    printf("    plt_index:            0x%zx\n", plt_index);
    printf("    text_section:         0x%p\n", text_section);
    printf("    plt_section_vaddr:    0x%016lx\n", plt_section_vaddr);
    printf("    got_plt_section_vaddr:0x%016lx\n", got_plt_section_vaddr);
    printf("    got_plt_index:        0x%08x\n", got_plt_index);
    printf("    text_section_vaddr:   0x%016lx\n", text_section_vaddr);
    printf("    index_func:           0x%08x\n", index_func);
    printf("    offset_path_instruction: 0x%zx\n", offset_path_instruction);
    printf("    sizeof_instruction:   0x%zx\n", sizeof_instruction);


    /**
     * se espera recibir la direccion virtual de la instruccion
     */
    uint64_t call_instruction_vaddr = text_section_vaddr;

    /**
     * Debemos obtener la entrada a la PLT de este simbolo, siempre debera ser el index_func + 1
     */
    uint64_t plt_entry_vaddr = GET_PLT_ENTRY_ADDR(plt_section_vaddr, plt_index);
    printf("    plt_entry_vaddr:      0x%016lx\n", plt_entry_vaddr);
    /**
     * calcular la direccion relativa de la instruccion a parchear, se realiza:
     *      (la direccion virtual de la instruccion + el tamaño de la instruccion) -
     *      (la direcion base virtual de la entrada a la PLT que queremos acceder )
     */
    int32_t rel32_instruction = (int32_t) (plt_entry_vaddr - (call_instruction_vaddr + sizeof_instruction));
    printf("    rel32_instruction:    0x%08x\n", (uint32_t)rel32_instruction);

    /**
     * Parcheamos la instruccion desde offset indicado:
     */
    *(int32_t *)(text_section + offset_path_instruction) = rel32_instruction;
    printf("    Patched instruction at offset 0x%zx\n", offset_path_instruction);

    /**
     * Ejemplo:
     * Debemos calcular el desplazamiento entre la segunda entrada de la GOT(GOT[1]) y la instruccion
     * push QWORD PTR [rip+GOT[1]_offset]", la primera entrada de la GOT contiene el "link_map" necesario
     * para llamar al linker
     * :
     *         // PLT0 (Offset 0 in .plt section, used for dynamic linker setup)
     *         // push QWORD PTR [rip+GOT[1]_offset]
     *         // This pushes the link_map pointer (GOT[1]) onto the stack.
     *         0xff, 0x35, 0,0,0,0,
     *         // jmp QWORD PTR [rip+GOT[2]_offset]
     *         // This jumps to the _dl_runtime_resolve function provided by the dynamic linker (GOT[2]).
     *         0xff, 0x25, 0,0,0,0,
     *         0x0f, 0x1f, 0x40, 0x00,          // nop dword ptr [rax+0x0] (padding for 16-byte alignment)
     *
     * Para acceder a la segunda entrada de la GOT, se debe multiplicar 8(tamaño de cada entrada) por el indice
     * al que queremos acceder "1" y sumar esto a la direccion base VIRTUAL de la GOT:
     *          got_plt_section_vaddr + 8 * 1 == GET_GOT_ENTRY_ADDR(got_plt_section_vaddr, 1)
     * Luego debermos acceder a la instruccion PUTS de la PLT[0], la cual ocupa 6 bytes la instruccion, por lo que lo
     * sumaremos a la direccion base de la PLT(PLT[0]) y restaremos las direcciones ya descritas, obteniendo una
     * diferencia el cual corresponde al offset que el push necesita
     */
    plt[plt_index].offset_jmp_got = (int32_t)(
        GET_GOT_ENTRY_ADDR(got_plt_section_vaddr, got_plt_index) -
        (GET_PLT_ENTRY_ADDR(plt_section_vaddr, plt_index) + 6) // push ocupa 6 bytes
    );

    plt[plt_index].offset_got = index_func; // indice de la funcion
    plt[plt_index].offset_jmp_plt_got = (int32_t)(plt_section_vaddr - GET_PLT_ENTRY_ADDR(plt_section_vaddr, (plt_index + 1)));
}

/**
 * Permite alinear una direccion de memoria de tamaño "size_alignment"
 * rellenando con valores nulos de por medio.
 * @param mem puntero de la memoria que alinear
 * @param current_file_offset tamaño ocupado de la memoria usada, mem - size es el inicio de mem.
 * @param size_alignment tamaño a alinear
* @return el nuevo tamaño, "current_file_offset - size" = cantidad de
* bytes nulos añadidos
 */
size_t align_file_offset_page(void* mem, size_t current_file_offset, size_t size_alignment) {
    if (current_file_offset % size_alignment != 0) {
        size_t padding = size_alignment - (current_file_offset % size_alignment);
        memset(mem + current_file_offset, 0, padding);
        current_file_offset += padding;
    }
    return current_file_offset;
}

/**
 * Construye la tabla .dynsym dinámicamente a partir de las librerías importadas
 *
 * @param libs Array de librerías importadas
 * @param num_libs Número de librerías
 * @param dynstr Buffer de strings dinámicos (.dynstr)
 * @param num_symbols [out] Recibe el número total de símbolos generados
 * @return Elf64_Sym* Array de símbolos (debe ser liberado por el caller)
 */
Elf64_Sym* build_dynsym(ImportLibrary* libs, size_t num_libs,
                         uint8_t* dynstr, size_t* num_symbols) {
    // Contar el total de funciones
    size_t total_functions = 0;
    for (size_t i = 0; i < num_libs; i++) {
        total_functions += libs[i].numFunctions;
    }

    // Reservar memoria (símbolo nulo + todas las funciones)
    *num_symbols = 1 + total_functions;
    Elf64_Sym* dynsym = calloc(*num_symbols, sizeof(Elf64_Sym));

    // Símbolo nulo (obligatorio, índice 0)
    dynsym[0].st_name = 0;
    dynsym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    dynsym[0].st_shndx = SHN_UNDEF;

    // Rellenar símbolos para cada función
    size_t symbol_index = 1;
    for (size_t lib_idx = 0; lib_idx < num_libs; lib_idx++) {
        for (size_t func_idx = 0; func_idx < libs[lib_idx].numFunctions; func_idx++) {
            const char* func_name = libs[lib_idx].functions[func_idx];

            dynsym[symbol_index].st_name = dynstr_find_offset(dynstr, func_name);
            dynsym[symbol_index].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
            dynsym[symbol_index].st_shndx = SHN_UNDEF;
            dynsym[symbol_index].st_value = 0;
            dynsym[symbol_index].st_size = 0;

            symbol_index++;
        }
    }

    return dynsym;
}

/**
 * Construye la tabla .rela.plt a partir de las funciones importadas.
 *
 * @param got_plt_vaddr Dirección virtual base de .got.plt
 * @param dynsym_start_idx Índice del primer símbolo importado en .dynsym (normalmente 1)
 * @param num_functions Número total de funciones importadas
 * @param num_rela [out] Recibe el número total de entradas .rela.plt
 * @return Elf64_Rela* Array de relocalizaciones (debe ser liberado por el caller)
 */
Elf64_Rela* build_rela_plt(uint64_t got_plt_vaddr, size_t dynsym_start_idx,
                           size_t num_functions, size_t* num_rela) {
    *num_rela = num_functions;
    Elf64_Rela* rela = calloc(*num_rela, sizeof(Elf64_Rela));
    for (size_t i = 0; i < num_functions; i++) {
        // GOT[3] para el primer símbolo importado, GOT[4] para el segundo, etc.
        // (Asumiendo que GOT[0], GOT[1], GOT[2] son reservados)
        rela[i].r_offset = got_plt_vaddr + (i + 3) * 8;
        rela[i].r_info = ELF64_R_INFO(dynsym_start_idx + i, R_X86_64_JUMP_SLOT);
        rela[i].r_addend = 0;
    }
    return rela;
}

/* =========================================================================
 *  elf_create_shared64 -- emisor de .so (ET_DYN) position-independent
 * ========================================================================= */

/* Buffer de salida con append + alineacion (local a este emisor). */
typedef struct { uint8_t *p; size_t len, cap; } ElfSoBuf;
static int eso_reserve(ElfSoBuf *o, size_t extra) {
    if (o->len + extra <= o->cap) return 1;
    size_t nc = o->cap ? o->cap * 2 : 8192;
    while (nc < o->len + extra) nc *= 2;
    uint8_t *np = (uint8_t *)realloc(o->p, nc);
    if (!np) return 0;
    o->p = np; o->cap = nc; return 1;
}
static int eso_put(ElfSoBuf *o, const void *data, size_t n) {
    if (!eso_reserve(o, n)) return 0;
    if (n) { if (data) memcpy(o->p + o->len, data, n); else memset(o->p + o->len, 0, n); }
    o->len += n; return 1;
}
static void eso_align(ElfSoBuf *o, size_t a) {
    while (o->len % a) { uint8_t z = 0; eso_put(o, &z, 1); }
}
static void eso_seterr(char *e, size_t cap, const char *m) {
    if (!e || !cap) return; size_t n = strlen(m); if (n >= cap) n = cap - 1;
    memcpy(e, m, n); e[n] = 0;
}

int elf_create_shared64(const char *path,
                        const ElfSharedSection *secs, int nsec,
                        const ElfSharedReloc *relocs, int nrel,
                        const ElfSharedExport *exps, int nexp,
                        char *errbuf, size_t errcap) {
    if (nsec <= 0) { eso_seterr(errbuf, errcap, "elf_create_shared64: sin secciones"); return 0; }
    for (int r = 0; r < nrel; ++r) {
        if (relocs[r].is_abs64) {
            eso_seterr(errbuf, errcap, "elf_create_shared64: ABS64 no soportado en .so (usa PIC)");
            return 0;
        }
        if (relocs[r].site_sec < 0 || relocs[r].site_sec >= nsec ||
            relocs[r].target_sec < 0 || relocs[r].target_sec >= nsec) {
            eso_seterr(errbuf, errcap, "elf_create_shared64: reloc con seccion fuera de rango");
            return 0;
        }
    }

    /* Section header indices: 0=NULL, 1..nsec user, +.dynsym,.dynstr,.hash,
     * .dynamic,.shstrtab. */
    const int dynsym_sh = 1 + nsec;
    const int dynstr_sh = dynsym_sh + 1;
    const int hash_sh   = dynstr_sh + 1;
    const int dyn_sh    = hash_sh + 1;
    const int shstr_sh  = dyn_sh + 1;
    const int shnum     = shstr_sh + 1;

    /* .dynstr + .dynsym (export symbols).  sym[0] = null. */
    ElfSoBuf dynstr; memset(&dynstr, 0, sizeof(dynstr));
    { uint8_t z = 0; eso_put(&dynstr, &z, 1); }
    const int nsym = 1 + nexp;
    Elf64_Sym *dynsym = (Elf64_Sym *)calloc((size_t)nsym, sizeof(Elf64_Sym));

    /* .shstrtab + nombres de seccion. */
    ElfSoBuf shstr; memset(&shstr, 0, sizeof(shstr));
    { uint8_t z = 0; eso_put(&shstr, &z, 1); }
    uint32_t *sec_nameoff = (uint32_t *)calloc((size_t)nsec, sizeof(uint32_t));
    for (int i = 0; i < nsec; ++i) {
        sec_nameoff[i] = (uint32_t)shstr.len;
        eso_put(&shstr, secs[i].name, strlen(secs[i].name) + 1);
    }
    uint32_t no_dynsym = (uint32_t)shstr.len; eso_put(&shstr, ".dynsym", 8);
    uint32_t no_dynstr = (uint32_t)shstr.len; eso_put(&shstr, ".dynstr", 8);
    uint32_t no_hash   = (uint32_t)shstr.len; eso_put(&shstr, ".hash", 6);
    uint32_t no_dyn    = (uint32_t)shstr.len; eso_put(&shstr, ".dynamic", 9);
    uint32_t no_shstr  = (uint32_t)shstr.len; eso_put(&shstr, ".shstrtab", 10);

    /* Construir el fichero.  Mapeo vaddr = offset (identidad). */
    ElfSoBuf out; memset(&out, 0, sizeof(out));
    Elf64_Ehdr eh; memset(&eh, 0, sizeof(eh));
    eh.e_ident[0]=0x7f; eh.e_ident[1]='E'; eh.e_ident[2]='L'; eh.e_ident[3]='F';
    eh.e_ident[4]=2; eh.e_ident[5]=1; eh.e_ident[6]=1;
    eh.e_type = ET_DYN; eh.e_machine = EM_X86_64; eh.e_version = 1;
    eh.e_ehsize = (Elf64_Half)sizeof(Elf64_Ehdr);
    eh.e_phentsize = (Elf64_Half)sizeof(Elf64_Phdr);
    eh.e_phnum = 3;  /* PT_LOAD + PT_DYNAMIC + PT_GNU_STACK */
    eh.e_phoff = sizeof(Elf64_Ehdr);
    eh.e_shentsize = (Elf64_Half)sizeof(Elf64_Shdr);
    eh.e_shnum = (Elf64_Half)shnum;
    eh.e_shstrndx = (Elf64_Half)shstr_sh;
    eso_put(&out, &eh, sizeof(eh));
    /* Reservar espacio de los 3 phdrs (se rellenan al final). */
    size_t phoff = out.len;
    { Elf64_Phdr zp; memset(&zp, 0, sizeof(zp));
      eso_put(&out, &zp, sizeof(zp)); eso_put(&out, &zp, sizeof(zp));
      eso_put(&out, &zp, sizeof(zp)); }

    /* Secciones de usuario (vaddr = offset). */
    uint64_t *sec_off = (uint64_t *)calloc((size_t)nsec, sizeof(uint64_t));
    for (int i = 0; i < nsec; ++i) {
        eso_align(&out, 16);
        sec_off[i] = out.len;
        eso_put(&out, secs[i].data, secs[i].size);
    }
    /* Aplicar relocs REL32 (PC-relativas). */
    for (int r = 0; r < nrel; ++r) {
        const ElfSharedReloc *rl = &relocs[r];
        uint64_t site_va = sec_off[rl->site_sec] + rl->site_off;
        uint64_t tgt_va  = sec_off[rl->target_sec] + rl->target_off;
        int32_t rel = (int32_t)((int64_t)tgt_va - (int64_t)site_va - 4);
        uint8_t *p = out.p + sec_off[rl->site_sec] + rl->site_off;
        p[0]=(uint8_t)rel; p[1]=(uint8_t)(rel>>8); p[2]=(uint8_t)(rel>>16); p[3]=(uint8_t)(rel>>24);
    }

    /* .dynsym (st_value = vaddr de cada export). */
    for (int g = 0; g < nexp; ++g) {
        Elf64_Sym *s = &dynsym[1 + g];
        s->st_name  = (Elf64_Word)dynstr.len;
        eso_put(&dynstr, exps[g].name, strlen(exps[g].name) + 1);
        s->st_info  = ELF64_ST_INFO(STB_GLOBAL, exps[g].is_func ? STT_FUNC : STT_OBJECT);
        s->st_shndx = (Elf64_Half)(1 + exps[g].sec);
        s->st_value = sec_off[exps[g].sec] + exps[g].off;
    }
    eso_align(&out, 8);
    uint64_t dynsym_off = out.len;
    eso_put(&out, dynsym, (size_t)nsym * sizeof(Elf64_Sym));
    uint64_t dynstr_off = out.len;
    eso_put(&out, dynstr.p, dynstr.len);

    /* .hash SysV: 1 bucket; cadena lineal sobre todos los simbolos. */
    eso_align(&out, 8);
    uint64_t hash_off = out.len;
    { uint32_t nb = 1, nc = (uint32_t)nsym;
      eso_put(&out, &nb, 4); eso_put(&out, &nc, 4);
      uint32_t bucket0 = (nsym > 1) ? 1u : 0u; eso_put(&out, &bucket0, 4);
      for (int i = 0; i < nsym; ++i) {
          uint32_t chain = (i + 1 < nsym) ? (uint32_t)(i + 1) : 0u;
          eso_put(&out, &chain, 4);
      } }
    uint64_t hash_size = out.len - hash_off;

    /* .dynamic. */
    eso_align(&out, 8);
    uint64_t dyn_off = out.len;
    { Elf64_Dyn d;
      #define ESO_DYN(tag, val) do { d.d_tag = (tag); d.d_un.d_val = (uint64_t)(val); eso_put(&out, &d, sizeof(d)); } while (0)
      ESO_DYN(DT_HASH, hash_off);
      ESO_DYN(DT_STRTAB, dynstr_off);
      ESO_DYN(DT_SYMTAB, dynsym_off);
      ESO_DYN(DT_STRSZ, dynstr.len);
      ESO_DYN(DT_SYMENT, sizeof(Elf64_Sym));
      ESO_DYN(DT_NULL, 0);
      #undef ESO_DYN
    }
    uint64_t dyn_size = out.len - dyn_off;

    /* .shstrtab. */
    uint64_t shstr_off = out.len;
    eso_put(&out, shstr.p, shstr.len);

    uint64_t load_end = out.len;  /* PT_LOAD cubre [0, load_end). */

    /* Tabla de section headers. */
    eso_align(&out, 8);
    uint64_t shoff = out.len;
    Elf64_Shdr *shdr = (Elf64_Shdr *)calloc((size_t)shnum, sizeof(Elf64_Shdr));
    for (int i = 0; i < nsec; ++i) {
        Elf64_Shdr *s = &shdr[1 + i];
        s->sh_name = sec_nameoff[i]; s->sh_type = SHT_PROGBITS;
        s->sh_flags = secs[i].sh_flags ? secs[i].sh_flags : SHF_ALLOC;
        s->sh_addr = sec_off[i]; s->sh_offset = sec_off[i]; s->sh_size = secs[i].size;
        s->sh_addralign = (secs[i].sh_flags & SHF_EXECINSTR) ? 16 : 8;
    }
    { Elf64_Shdr *s = &shdr[dynsym_sh];
      s->sh_name = no_dynsym; s->sh_type = SHT_DYNSYM; s->sh_flags = SHF_ALLOC;
      s->sh_addr = dynsym_off; s->sh_offset = dynsym_off;
      s->sh_size = (uint64_t)nsym * sizeof(Elf64_Sym);
      s->sh_link = (Elf64_Word)dynstr_sh; s->sh_info = 1;
      s->sh_addralign = 8; s->sh_entsize = sizeof(Elf64_Sym); }
    { Elf64_Shdr *s = &shdr[dynstr_sh];
      s->sh_name = no_dynstr; s->sh_type = SHT_STRTAB; s->sh_flags = SHF_ALLOC;
      s->sh_addr = dynstr_off; s->sh_offset = dynstr_off; s->sh_size = dynstr.len;
      s->sh_addralign = 1; }
    { Elf64_Shdr *s = &shdr[hash_sh];
      s->sh_name = no_hash; s->sh_type = SHT_HASH; s->sh_flags = SHF_ALLOC;
      s->sh_addr = hash_off; s->sh_offset = hash_off; s->sh_size = hash_size;
      s->sh_link = (Elf64_Word)dynsym_sh; s->sh_addralign = 8; s->sh_entsize = 4; }
    { Elf64_Shdr *s = &shdr[dyn_sh];
      s->sh_name = no_dyn; s->sh_type = SHT_DYNAMIC; s->sh_flags = SHF_ALLOC | SHF_WRITE;
      s->sh_addr = dyn_off; s->sh_offset = dyn_off; s->sh_size = dyn_size;
      s->sh_link = (Elf64_Word)dynstr_sh; s->sh_addralign = 8; s->sh_entsize = sizeof(Elf64_Dyn); }
    { Elf64_Shdr *s = &shdr[shstr_sh];
      s->sh_name = no_shstr; s->sh_type = SHT_STRTAB;
      s->sh_offset = shstr_off; s->sh_size = shstr.len; s->sh_addralign = 1; }
    eso_put(&out, shdr, (size_t)shnum * sizeof(Elf64_Shdr));

    /* Rellenar ehdr.e_shoff + los 2 program headers. */
    ((Elf64_Ehdr *)out.p)->e_shoff = shoff;
    Elf64_Phdr *ph = (Elf64_Phdr *)(out.p + phoff);
    ph[0].p_type = PT_LOAD; ph[0].p_flags = PF_R | PF_W | PF_X;
    ph[0].p_offset = 0; ph[0].p_vaddr = 0; ph[0].p_paddr = 0;
    ph[0].p_filesz = load_end; ph[0].p_memsz = load_end; ph[0].p_align = 0x1000;
    ph[1].p_type = PT_DYNAMIC; ph[1].p_flags = PF_R | PF_W;
    ph[1].p_offset = dyn_off; ph[1].p_vaddr = dyn_off; ph[1].p_paddr = dyn_off;
    ph[1].p_filesz = dyn_size; ph[1].p_memsz = dyn_size; ph[1].p_align = 8;
    /* PT_GNU_STACK (R+W, NO ejecutable): sin el, el loader asume stack
     * ejecutable y dlopen falla en sistemas endurecidos. */
    ph[2].p_type = 0x6474e551u; ph[2].p_flags = PF_R | PF_W;
    ph[2].p_offset = 0; ph[2].p_vaddr = 0; ph[2].p_paddr = 0;
    ph[2].p_filesz = 0; ph[2].p_memsz = 0; ph[2].p_align = 0x10;

    int ok = 1;
    FILE *f = fopen(path, "wb");
    if (!f) { eso_seterr(errbuf, errcap, "elf_create_shared64: fopen fallo"); ok = 0; }
    else { size_t w = fwrite(out.p, 1, out.len, f); fclose(f);
           if (w != out.len) { eso_seterr(errbuf, errcap, "elf_create_shared64: escritura incompleta"); ok = 0; } }

    free(dynsym); free(dynstr.p); free(shstr.p); free(sec_nameoff);
    free(sec_off); free(shdr); free(out.p);
    return ok;
}


#endif // CREATE_ELF_C