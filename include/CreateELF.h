#ifndef CREATE_ELF_H
#define CREATE_ELF_H

#include "CreatePe.h"

#define PAGE_SIZE 0x1000

// https://stevens.netmeister.org/631/elf.html
// https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=sysdeps/x86_64/dl-machine.h
// RIP -> https://www.tortall.net/projects/yasm/manual/html/nasm-effaddr.html

#include "LibELFparse.h"

// ELF Identification indices (posiciones dentro de e_ident)
#ifndef EI_MAG0
#define EI_MAG0         0
#endif
#ifndef EI_MAG1
#define EI_MAG1         1
#endif
#ifndef EI_MAG2
#define EI_MAG2         2
#endif
#ifndef EI_MAG3
#define EI_MAG3         3
#endif
#ifndef EI_CLASS
#define EI_CLASS        4
#endif
#ifndef EI_DATA
#define EI_DATA         5
#endif
#ifndef EI_VERSION
#define EI_VERSION      6
#endif
#ifndef EI_OSABI
#define EI_OSABI        7
#endif
#ifndef EI_ABIVERSION
#define EI_ABIVERSION   8
#endif

/* Las constantes del formato ELF van CADA UNA con su guarda.
 *
 * La cabecera tiene que seguir siendo autosuficiente: si el compilador o la
 * plataforma no las trae, aqui estan.  Pero muchas de estas ya las define
 * LibELFparse.h -- la otra mitad de esta misma libreria, que se incluye arriba:
 * alli se leen los ELF y aqui se escriben, y las constantes del formato son
 * unas --, y algunas plataformas las traen ademas en su <elf.h>.
 *
 * Sin la guarda, definirlas otra vez con el mismo valor escrito de otra forma
 * -- 0x7f frente a 0x7F, 2 frente a (2), 11 frente a 0xb -- es una violacion de
 * restriccion: con -pedantic-errors deja de ser aviso y pasa a error, y ese era
 * el unico motivo de que esta cabecera no compilase como C++.  Con la guarda,
 * gana quien llegue primero y no se define nada dos veces.
 *
 * La guarda va por macro, no por bloque: LibELFparse.h define casi todas las
 * SHT_* pero no SHT_SHLIB, asi que un solo #ifndef alrededor del grupo dejaria
 * fuera justo la que no viene de ningun otro sitio. */

#ifndef ELFMAG0
#define ELFMAG0 0x7f
#endif
#ifndef ELFMAG1
#define ELFMAG1 'E'
#endif
#ifndef ELFMAG2
#define ELFMAG2 'L'
#endif
#ifndef ELFMAG3
#define ELFMAG3 'F'
#endif

// ELF Class
#ifndef ELFCLASS64
#define ELFCLASS64 2
#endif

// ELF Data encoding
#ifndef ELFDATA2LSB
#define ELFDATA2LSB 1
#endif

// ELF Version
#ifndef EV_CURRENT
#define EV_CURRENT 1
#endif

// ELF OS/ABI
#ifndef ELFOSABI_SYSV
#define ELFOSABI_SYSV 0
#endif

// ELF Type
#ifndef ET_EXEC
#define ET_EXEC 2
#endif

// ELF Machine
#ifndef EM_X86_64
#define EM_X86_64 62
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183 // ARM 64-bit (AArch64)
#endif

/* Aqui habia un segundo juego de EI_MAG0..EI_ABIVERSION, copia literal del de
 * arriba y sin guarda.  No daba error porque los valores coincidian token a
 * token, pero anulaba la guarda del primero: en una plataforma que ya trajera
 * esos indices, la copia los redefinia igualmente. */

// Section Header Types
#ifndef SHT_NULL
#define SHT_NULL 0
#endif
#ifndef SHT_PROGBITS
#define SHT_PROGBITS 1
#endif
#ifndef SHT_SYMTAB
#define SHT_SYMTAB 2
#endif
#ifndef SHT_STRTAB
#define SHT_STRTAB 3
#endif
#ifndef SHT_RELA
#define SHT_RELA 4
#endif
#ifndef SHT_HASH
#define SHT_HASH 5
#endif
#ifndef SHT_DYNAMIC
#define SHT_DYNAMIC 6
#endif
#ifndef SHT_NOTE
#define SHT_NOTE 7
#endif
#ifndef SHT_NOBITS
#define SHT_NOBITS 8
#endif
#ifndef SHT_REL
#define SHT_REL 9
#endif
#ifndef SHT_SHLIB
#define SHT_SHLIB 10
#endif
#ifndef SHT_DYNSYM
#define SHT_DYNSYM 11
#endif

// Section Header Flags
#ifndef SHF_WRITE
#define SHF_WRITE 0x1
#endif
#ifndef SHF_ALLOC
#define SHF_ALLOC 0x2
#endif
#ifndef SHF_EXECINSTR
#define SHF_EXECINSTR 0x4
#endif

// Program Header Types
#ifndef PT_NULL
#define PT_NULL 0
#endif
#ifndef PT_LOAD
#define PT_LOAD 1
#endif
#ifndef PT_DYNAMIC
#define PT_DYNAMIC 2
#endif
#ifndef PT_INTERP
#define PT_INTERP 3
#endif
#ifndef PT_NOTE
#define PT_NOTE 4
#endif
#ifndef PT_SHLIB
#define PT_SHLIB 5
#endif
#ifndef PT_PHDR
#define PT_PHDR 6
#endif

// Program Header Flags
#ifndef PF_X
#define PF_X 0x1
#endif
#ifndef PF_W
#define PF_W 0x2
#endif
#ifndef PF_R
#define PF_R 0x4
#endif

// Symbol Table
#ifndef STB_LOCAL
#define STB_LOCAL 0
#endif
#ifndef STB_GLOBAL
#define STB_GLOBAL 1
#endif
#ifndef STB_WEAK
#define STB_WEAK 2
#endif

#ifndef STT_NOTYPE
#define STT_NOTYPE 0
#endif
#ifndef STT_OBJECT
#define STT_OBJECT 1
#endif
#ifndef STT_FUNC
#define STT_FUNC 2
#endif
#ifndef STT_SECTION
#define STT_SECTION 3
#endif
#ifndef STT_FILE
#define STT_FILE 4
#endif

#ifndef SHN_UNDEF
#define SHN_UNDEF 0
#endif

// Dynamic Tags
#ifndef DT_NULL
#define DT_NULL 0
#endif
#ifndef DT_NEEDED
#define DT_NEEDED 1
#endif
#ifndef DT_PLTRELSZ
#define DT_PLTRELSZ 2
#endif
#ifndef DT_PLTGOT
#define DT_PLTGOT 3
#endif
#ifndef DT_HASH
#define DT_HASH 4
#endif
#ifndef DT_STRTAB
#define DT_STRTAB 5
#endif
#ifndef DT_SYMTAB
#define DT_SYMTAB 6
#endif
#ifndef DT_RELA
#define DT_RELA 7
#endif
#ifndef DT_RELASZ
#define DT_RELASZ 8
#endif
#ifndef DT_RELAENT
#define DT_RELAENT 9
#endif
#ifndef DT_STRSZ
#define DT_STRSZ 10
#endif
#ifndef DT_SYMENT
#define DT_SYMENT 11
#endif
#ifndef DT_INIT
#define DT_INIT 12
#endif
#ifndef DT_FINI
#define DT_FINI 13
#endif
#ifndef DT_SONAME
#define DT_SONAME 14
#endif
#ifndef DT_RPATH
#define DT_RPATH 15
#endif
#ifndef DT_SYMBOLIC
#define DT_SYMBOLIC 16
#endif
#ifndef DT_REL
#define DT_REL 17
#endif
#ifndef DT_RELSZ
#define DT_RELSZ 18
#endif
#ifndef DT_RELENT
#define DT_RELENT 19
#endif
#ifndef DT_PLTREL
#define DT_PLTREL 20
#endif
#ifndef DT_DEBUG
#define DT_DEBUG 21
#endif
#ifndef DT_TEXTREL
#define DT_TEXTREL 22
#endif
#ifndef DT_JMPREL
#define DT_JMPREL 23
#endif

// Relocation Types
#ifndef R_X86_64_NONE
#define R_X86_64_NONE 0
#endif
#ifndef R_X86_64_64
#define R_X86_64_64 1
#endif
#ifndef R_X86_64_PC32
#define R_X86_64_PC32 2
#endif
#ifndef R_X86_64_GOT32
#define R_X86_64_GOT32 3
#endif
#ifndef R_X86_64_PLT32
#define R_X86_64_PLT32 4
#endif
#ifndef R_X86_64_COPY
#define R_X86_64_COPY 5
#endif
#ifndef R_X86_64_GLOB_DAT
#define R_X86_64_GLOB_DAT 6
#endif
#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT 7
#endif
#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE 8
#endif

/**
 * Permite obtener la direccion a la entrada de la GOT especificada, cada entrada ocupa 8 bytes(un puntero)
 * @param address_got direccion absoluta, o relativa o virtual a la GOT
 * @param index indice de la entrada
 */
#define GET_GOT_ENTRY_ADDR(address_got, index) (address_got + 8 * (index))

/**
 * Permite obtener la direccion a la entrada de la PLT especificada, cada entrada ocupa 16 bytes(normalmente)
 * @param address_plt direccion absoluta, o relativa o virtual a la PLT
 * @param index indice de la entrada
 */
#define GET_PLT_ENTRY_ADDR(address_plt, index) (address_plt + 16 * (index))

typedef struct {
    uint8_t *mem;        // Main buffer for the ELF image
    size_t capacity;     // Total capacity of the buffer
    size_t size;         // Current used size of the buffer
    int is64;            // 1 for 64-bit, 0 for 32-bit
    uint16_t machine;    // e_machine (EM_X86_64 por defecto; EM_AARCH64 para ARM)

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

// Fija la arquitectura (e_machine) del ELF a generar.  Por defecto EM_X86_64;
// llamar con EM_AARCH64 para producir un ELF de ARM 64-bit.  Afecta al
// e_machine que escribe elf_builder_finalize_exec64.
void elf_builder_set_machine(ElfBuilder *b, uint16_t machine);


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
/* Los struct sin nombre van marcados con __C89_NAMELESS.
 *
 * Un struct anonimo es C11 valido, pero en C++ es una extension: ISO C++ solo
 * admite anonimas las UNIONES, y por eso las de aqui no llevan marca.  Con
 * -pedantic-errors el compilador esta obligado a rechazarlo, y sin la marca
 * esta cabecera no se puede incluir desde C++.
 *
 * __C89_NAMELESS es el mecanismo que la propia libreria ya trae (LibPEparse.h,
 * copiado de las cabeceras de MinGW, que resuelven esto mismo): se expande a
 * __extension__ en GCC y Clang -- "esto es una extension y lo se", que es
 * exactamente lo que hay que decir -- y a nada en el resto, donde no estorba.
 * No cambia la disposicion en memoria: los nombres de los campos se siguen
 * usando sin cualificar. */
typedef struct plt_entry_t{
    union {
        __C89_NAMELESS struct {
            union {
                uint8_t jmp_got[6];                 // jmp QWORD PTR [rip + offset_to_GOT]
                __C89_NAMELESS struct {
                    uint16_t opcode_jmp_got_rip;    // opcode 0xff, 0x25 == jmp QWORD PTR
                    uint32_t offset_jmp_got;        // [rip + offset_to_GOT]
                };
            };
            union {
                uint8_t push[5];                    // push <relocation_index>
                __C89_NAMELESS struct {
                    uint8_t opcode_push;            // 0x68 opcode == push
                    uint32_t offset_got;            // relocation_index
                };
            };
            union {
                uint8_t jmp_plt[5];                 // jmp <plt0>
                __C89_NAMELESS struct {
                    uint8_t opcode_jmp_plt;         // opcode 0xff, 0x25 == jmp QWORD PTR
                    uint32_t offset_jmp_plt_got;    // [rip + offset_to_GOT]
                };
            };
        };
        // cada entrada son 16 bytes
        uint8_t raw[16];
    };
} plt_entry_t;
plt_entry_t* init_plt_table(size_t number_entry);

size_t align_file_offset_page(void* mem, size_t current_file_offset, size_t size_alignment);

void init_plt0(
    plt_entry_t *plt,
    uint64_t plt_section_vaddr,
    uint64_t got_plt_section_vaddr
);
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
);

void print_dynstr(const char* dynstr, size_t length);
char* join_string_libs_func(ImportLibrary* libs_with_funcs, size_t number_libs, size_t* size_output);
size_t dynstr_find_offset(const char* dynstr, const char* target);
Elf64_Sym* build_dynsym(ImportLibrary* libs, size_t num_libs,
                         uint8_t* dynstr, size_t* num_symbols);
Elf64_Rela* build_rela_plt(uint64_t got_plt_vaddr, size_t dynsym_start_idx,
                           size_t num_functions, size_t* num_rela);
// Libera todos los recursos asociados con el ElfBuilder
void elf_builder_free(ElfBuilder *b);

/* =========================================================================
 *  Emisor de libreria compartida ELF64 (.so, ET_DYN)
 *
 *  Genera un objeto compartido POSITION-INDEPENDENT: el mapeo es vaddr=offset
 *  (identidad) con un unico PT_LOAD (R+W+X) + PT_DYNAMIC.  Las relocs internas
 *  REL32 (RIP-relativas) se APLICAN al emitir (su desplazamiento es invariante
 *  bajo la base de carga), por lo que NO se generan relocs dinamicas.  Los
 *  simbolos se exportan en .dynsym + .hash + .dynamic, de forma que el cargador
 *  dinamico (dlopen/dlsym) los resuelva.  ABS64 no se soporta (requeriria
 *  R_X86_64_RELATIVE dinamicas).
 * ========================================================================= */

/** @brief Seccion de entrada para @c elf_create_shared64. */
typedef struct {
    const char    *name;      /* ".text", ".rodata", ... */
    uint64_t       sh_flags;  /* SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE */
    const uint8_t *data;      /* bytes de la seccion */
    uint32_t       size;      /* tamano */
} ElfSharedSection;

/** @brief Relocation interna (PC-relativa) a aplicar en el .so. */
typedef struct {
    int      site_sec;    /* seccion donde parchear */
    uint64_t site_off;    /* offset del campo */
    int      target_sec;  /* seccion objetivo */
    uint64_t target_off;  /* offset dentro del target */
    int      is_abs64;    /* 0 = REL32 (rip-rel, aplicada); 1 = ABS64 (no soportado) */
} ElfSharedReloc;

/** @brief Simbolo GLOBAL exportado por el .so. */
typedef struct {
    const char *name;
    int      sec;       /* seccion donde vive */
    uint64_t off;       /* offset dentro de la seccion */
    int      is_func;   /* 1 = STT_FUNC, 0 = STT_OBJECT */
} ElfSharedExport;

/**
 * @brief Emite un .so ET_DYN a disco.
 * @return 1 en exito, 0 en error (con @p errbuf relleno si != NULL).
 */
int elf_create_shared64(const char *path,
                        const ElfSharedSection *secs, int nsec,
                        const ElfSharedReloc *relocs, int nrel,
                        const ElfSharedExport *exps, int nexp,
                        char *errbuf, size_t errcap);
#endif // CREATE_ELF_H