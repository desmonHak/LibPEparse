#ifndef CREATE_ELF_C
#define CREATE_ELF_C

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "CreateELF.h"
#include "LibELFparse.h"

ElfBuilder *elf_builder_create_exec64(size_t capacity) {
    ElfBuilder *b = calloc(1, sizeof(ElfBuilder));
    if (!b) return NULL;

    b->mem = calloc(1, capacity);
    if (!b->mem) {
        free(b);
        return NULL;
    }

    b->capacity = capacity;
    b->size = 0;
    b->is64 = 1;

    // Inicializar shstrtab con un byte nulo inicial
    b->shstrtab_cap = 256;
    b->shstrtab = calloc(1, b->shstrtab_cap);
    if (!b->shstrtab) {
        free(b->mem);
        free(b);
        return NULL;
    }
    b->shstrtab_len = 1; // Primer byte siempre es nulo

    // Reservar espacio para header y program header
    b->ehdr = b->mem;
    b->size = sizeof(Elf64_Header);
    b->phdr = b->mem + b->size;
    b->size += sizeof(Elf64_Phdr);

    // Inicializar la tabla de secciones (temporalmente)
    b->shdr = calloc(32, sizeof(Elf64_Shdr)); // Espacio para 32 secciones
    if (!b->shdr) {
        free(b->shstrtab);
        free(b->mem);
        free(b);
        return NULL;
    }

    // Inicializar con una sección NULL (obligatoria)
    b->shnum = 1;
    b->phnum = 1;
    b->shstrndx = 0;

    return b;
}

size_t elf_builder_add_section(ElfBuilder *b, const char *name, uint32_t type, uint64_t flags,
                               const void *data, size_t size, uint64_t vaddr, uint64_t align,
                               size_t *out_offset, uint64_t *out_vaddr) {
    // Alineación de offset de archivo
    size_t align_mask = align ? align - 1 : 0;
    if (align && (b->size & align_mask)) {
        b->size = (b->size + align_mask) & ~align_mask;
    }
    size_t file_off = b->size;

    // Alineación de dirección virtual
    uint64_t va = vaddr;
    if (align && (va & align_mask)) {
        va = (va + align_mask) & ~align_mask;
    }

    // Copia el nombre a shstrtab
    size_t name_off = b->shstrtab_len;
    size_t namelen = strlen(name) + 1;
    if (b->shstrtab_len + namelen > b->shstrtab_cap) {
        size_t new_cap = b->shstrtab_cap * 2;
        char *new_strtab = realloc(b->shstrtab, new_cap);
        if (!new_strtab) return 0;
        b->shstrtab = new_strtab;
        b->shstrtab_cap = new_cap;
    }
    memcpy(b->shstrtab + b->shstrtab_len, name, namelen);
    b->shstrtab_len += namelen;

    // Copia los datos de la sección
    if (data && size) {
        memcpy(b->mem + file_off, data, size);
        b->size = file_off + size;
    }

    // Descriptor de sección
    Elf64_Shdr *shdr = (Elf64_Shdr *)b->shdr;
    Elf64_Shdr *s = &shdr[b->shnum];
    memset(s, 0, sizeof(*s));
    s->sh_name = name_off;
    s->sh_type = type;
    s->sh_flags = flags;
    s->sh_addr = va;
    s->sh_offset = file_off;
    s->sh_size = size;
    s->sh_addralign = align ? align : 1;

    if (out_offset) *out_offset = file_off;
    if (out_vaddr)  *out_vaddr = va;
    return b->shnum++;
}

// Finaliza el ELF ejecutable
void elf_builder_finalize_exec64(ElfBuilder *b, uint64_t entry, size_t code_file_off, uint64_t code_vaddr, size_t code_size) {
    // Añadir la sección .shstrtab si no existe
    size_t shstrtab_name_off = b->shstrtab_len;
    const char *shstrtab_name = ".shstrtab";
    size_t shstrtab_namelen = strlen(shstrtab_name) + 1;

    // Asegurar capacidad en shstrtab
    if (b->shstrtab_len + shstrtab_namelen > b->shstrtab_cap) {
        size_t new_cap = b->shstrtab_cap * 2;
        char *new_strtab = realloc(b->shstrtab, new_cap);
        if (!new_strtab) return;
        b->shstrtab = new_strtab;
        b->shstrtab_cap = new_cap;
    }

    // Añadir nombre de sección
    memcpy(b->shstrtab + b->shstrtab_len, shstrtab_name, shstrtab_namelen);
    b->shstrtab_len += shstrtab_namelen;

    // Alinear el offset para una mejor compatibilidad
    if (b->size % 4 != 0) {
        b->size = (b->size + 3) & ~3;
    }

    // Añadir el contenido de .shstrtab
    size_t shstrtab_off = b->size;
    memcpy(b->mem + shstrtab_off, b->shstrtab, b->shstrtab_len);
    b->size += b->shstrtab_len;

    // Añadir el descriptor de sección para .shstrtab
    Elf64_Shdr *shdr = (Elf64_Shdr *)b->shdr;
    Elf64_Shdr *s = &shdr[b->shnum];
    memset(s, 0, sizeof(*s));
    s->sh_name = shstrtab_name_off;
    s->sh_type = SHT_STRTAB;
    s->sh_offset = shstrtab_off;
    s->sh_size = b->shstrtab_len;
    s->sh_addralign = 1;
    b->shstrndx = b->shnum;
    b->shnum++;

    // Alinear el offset para la tabla de secciones (opcional pero recomendado)
    if (b->size % 8 != 0) {
        b->size = (b->size + 7) & ~7;
    }

    // Copiar la tabla de secciones al final del archivo
    size_t shdr_offset = b->size;
    memcpy(b->mem + shdr_offset, b->shdr, b->shnum * sizeof(Elf64_Shdr));
    b->size += b->shnum * sizeof(Elf64_Shdr);

    // Configurar el ELF header
    Elf64_Header *ehdr = (Elf64_Header *)b->ehdr;
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
    ehdr->e_entry = entry;
    ehdr->e_phoff = sizeof(Elf64_Header);
    ehdr->e_shoff = shdr_offset;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(Elf64_Header);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = b->phnum;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_shnum = b->shnum;
    ehdr->e_shstrndx = b->shstrndx;

    // Configurar el Program Header
    Elf64_Phdr *phdr = (Elf64_Phdr *)b->phdr;
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_offset = code_file_off;
    phdr->p_vaddr = code_vaddr;
    phdr->p_paddr = code_vaddr;
    phdr->p_filesz = code_size;
    phdr->p_memsz = code_size;
    phdr->p_flags = PF_X | PF_R;
    phdr->p_align = PAGE_SIZE;
}

void elf_builder_free(ElfBuilder *b) {
    if (b) {
        free(b->mem);
        free(b->shstrtab);
        free(b->shdr);
        free(b);
    }
}

#endif