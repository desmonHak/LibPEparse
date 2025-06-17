#ifndef CREATE_ELF_H
#define CREATE_ELF_H

#include "CreatePe.h"

#define PAGE_SIZE 0x1000

// https://stevens.netmeister.org/631/elf.html
// https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=sysdeps/x86_64/dl-machine.h
// RIP -> https://www.tortall.net/projects/yasm/manual/html/nasm-effaddr.html

#include "LibELFparse.h"
#ifndef EI_MAG0
#define EI_MAG0         0
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4
#define EI_DATA         5
#define EI_VERSION      6
#define EI_OSABI        7
#define EI_ABIVERSION   8
#endif

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

// ELF Class
#define ELFCLASS64 2

// ELF Data encoding
#define ELFDATA2LSB 1

// ELF Version
#define EV_CURRENT 1

// ELF OS/ABI
#define ELFOSABI_SYSV 0

// ELF Type
#define ET_EXEC 2

// ELF Machine
#define EM_X86_64 62

// ELF Identification indices
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_ABIVERSION 8

// Section Header Types
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11

// Section Header Flags
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4

// Program Header Types
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6

// Program Header Flags
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

// Symbol Table
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4

#define SHN_UNDEF 0

// Dynamic Tags
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_FINI 13
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_SYMBOLIC 16
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_PLTREL 20
#define DT_DEBUG 21
#define DT_TEXTREL 22
#define DT_JMPREL 23

// Relocation Types
#define R_X86_64_NONE 0
#define R_X86_64_64 1
#define R_X86_64_PC32 2
#define R_X86_64_GOT32 3
#define R_X86_64_PLT32 4
#define R_X86_64_COPY 5
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE 8

typedef struct {
    uint8_t *mem;        // Main buffer for the ELF image
    size_t capacity;     // Total capacity of the buffer
    size_t size;         // Current used size of the buffer
    int is64;            // 1 for 64-bit, 0 for 32-bit

    // Pointers to the main structures within `mem`
    void *ehdr;          // ELF header (points to start of `mem`)
    void *phdr;          // Program headers (points into `mem` after ehdr)
    void *shdr_temp;     // Temporary Section headers table (allocated separately, copied to `mem` later)
    size_t shnum;        // Number of sections
    size_t phnum;        // Number of program headers (fixed for this exec)
    size_t shstrndx;     // Index of the .shstrtab section

    // Dynamic string table for section names (.shstrtab content)
    char *shstrtab;      // Content of .shstrtab (dynamic buffer)
    size_t shstrtab_cap; // Capacity of shstrtab buffer
    size_t shstrtab_len; // Current length of shstrtab buffer

    // Creates an ElfBuilder for generating a 64-bit executable
    // capacity: Estimated maximum size for the ELF file
} ElfBuilder;

// Crea un ElfBuilder para generar un ejecutable de 64 bits
// capacity: Tamaño máximo estimado para el archivo ELF
ElfBuilder *elf_builder_create_exec64(size_t capacity, size_t number_program_headers);


// Añade una sección al ELF
// name: Nombre de la sección (ej: ".text")
// type: Tipo de sección (ej: SHT_PROGBITS)
// flags: Flags de sección (ej: SHF_ALLOC | SHF_EXECINSTR)
// data: Puntero a los datos de la sección
// size: Tamaño de los datos
// vaddr: Dirección virtual donde se cargará la sección
// align: Alineación de la sección (ej: 16, 4096)
// out_offset: [Opcional] Devuelve el offset de archivo donde se escribió la sección
// out_vaddr: [Opcional] Devuelve la dirección virtual ajustada
// Devuelve: Índice de la sección añadida
size_t elf_builder_add_section(
    ElfBuilder *b,
    const char *name,
    uint32_t type,
    uint64_t flags,
    const void *data,
    size_t size,
    uint64_t vaddr,
    uint64_t align,
    size_t *out_offset,
    uint64_t *out_vaddr
);

// Finalizes the ELF executable by populating the ELF header and copying the section header table.
// entry: Entry point virtual address
// Program headers are expected to be set up by the caller.
void elf_builder_finalize_exec64(
    ElfBuilder *b,
    uint64_t entry
);

// Adds a section to the ELF with extended attributes
// name: Section name (e.g., ".text")
// type: Section type (e.g., SHT_PROGBITS)
// flags: Section flags (e.g., SHF_ALLOC | SHF_EXECINSTR)
// data: Pointer to section data
// size: Size of data
// vaddr: Virtual address where section will be loaded
// align: Section alignment (e.g., 16, 4096)
// out_offset: [Optional] Returns file offset where section was written
// out_vaddr: [Optional] Returns adjusted virtual address
// sh_link, sh_info, sh_entsize: Extended section header fields
// Returns: Index of the added section (0 on failure)
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
);


// Libera todos los recursos asociados con el ElfBuilder
void elf_builder_free(ElfBuilder *b);
#endif // CREATE_ELF_H