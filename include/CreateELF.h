#ifndef CREATE_ELF_H
#define CREATE_ELF_H
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



typedef struct {
    uint8_t *mem;        // Buffer principal para la imagen ELF
    size_t capacity;     // Capacidad total del buffer
    size_t size;         // Tamaño actual utilizado
    int is64;            // 1 para 64-bit, 0 para 32-bit

    // Punteros a las estructuras principales
    void *ehdr;          // ELF header
    void *shdr;          // Section headers (tabla temporal)
    void *phdr;          // Program headers
    size_t shnum;        // Número de secciones
    size_t phnum;        // Número de program headers
    size_t shstrndx;     // Índice de la sección .shstrtab

    // Tabla de strings dinámica para nombres de secciones
    char *shstrtab;      // Contenido de .shstrtab
    size_t shstrtab_cap; // Capacidad de shstrtab
    size_t shstrtab_len; // Longitud actual de shstrtab
} ElfBuilder;

// Crea un ElfBuilder para generar un ejecutable de 64 bits
// capacity: Tamaño máximo estimado para el archivo ELF
ElfBuilder *elf_builder_create_exec64(size_t capacity);

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

// Finaliza el ELF ejecutable
// entry: Punto de entrada (dirección virtual)
// code_file_off: Offset en el archivo de la sección de código
// code_vaddr: Dirección virtual de la sección de código
// code_size: Tamaño de la sección de código
void elf_builder_finalize_exec64(
    ElfBuilder *b,
    uint64_t entry,
    size_t code_file_off,
    uint64_t code_vaddr,
    size_t code_size
);

// Libera todos los recursos asociados con el ElfBuilder
void elf_builder_free(ElfBuilder *b);
#endif // CREATE_ELF_H