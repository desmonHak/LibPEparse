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



#endif // CREATE_ELF_C