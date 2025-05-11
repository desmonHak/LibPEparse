
#ifndef LIB_ELF_PARSE_C
#define LIB_ELF_PARSE_C

#include "LibELFparse.h"

#include <inttypes.h>
#include <stdatomic.h>

#include "UtilsC.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Helper para imprimir bytes en hexadecimal
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

// Definicion de una tabla global de simbolos
typedef struct {
    const char *name;
    void *address;
} SymbolEntry;

static SymbolEntry global_symbols[] = {
     {"puts", (void*)puts},
     {"printf", (void*)printf},
    // simbolos globales
    {NULL, NULL}
};

void *elf_lookup_symbol(const char *name) {
    printf("elf_lookup_symbol -> %s ", name);
    for (int i = 0; global_symbols[i].name != NULL; ++i) {
        if (strcmp(global_symbols[i].name, name) == 0) {
            printf("%p\n", global_symbols[i].address);
            return global_symbols[i].address;
        }
    }
    printf("\n");

    return NULL;
}


typedef struct {
    uint64_t tag;
    const char *name;
} DynTagName;

static const DynTagName dyn_tags[] = {
    {0,        "DT_NULL"},
    {1,        "DT_NEEDED"},
    {2,        "DT_PLTRELSZ"},
    {3,        "DT_PLTGOT"},
    {4,        "DT_HASH"},
    {5,        "DT_STRTAB"},
    {6,        "DT_SYMTAB"},
    {7,        "DT_RELA"},
    {8,        "DT_RELASZ"},
    {9,        "DT_RELAENT"},
    {10,       "DT_STRSZ"},
    {11,       "DT_SYMENT"},
    {12,       "DT_INIT"},
    {13,       "DT_FINI"},
    {14,       "DT_SONAME"},
    {15,       "DT_RPATH"},
    {16,       "DT_SYMBOLIC"},
    {17,       "DT_REL"},
    {18,       "DT_RELSZ"},
    {19,       "DT_RELENT"},
    {20,       "DT_PLTREL"},
    {21,       "DT_DEBUG"},
    {22,       "DT_TEXTREL"},
    {23,       "DT_JMPREL"},
    {24,       "DT_BIND_NOW"},
    {25,       "DT_INIT_ARRAY"},
    {26,       "DT_FINI_ARRAY"},
    {27,       "DT_INIT_ARRAYSZ"},
    {28,       "DT_FINI_ARRAYSZ"},
    {29,       "DT_RUNPATH"},
    {30,       "DT_FLAGS"},
    {32,       "DT_PREINIT_ARRAY"},
    {33,       "DT_PREINIT_ARRAYSZ"},
    {0x6ffffef5,"DT_GNU_HASH"},
    {0x6ffffffb,"DT_FLAGS_1"},
    {0x6ffffffe,"DT_VERNEED"},
    {0x6fffffff,"DT_VERNEEDNUM"},
    {0x6ffffff0,"DT_VERSYM"},
    {0x6ffffff9,"DT_RELACOUNT"},
    {0, NULL}
};

const char *dyn_tag_name(uint64_t tag) {
    for (int i = 0; dyn_tags[i].name; ++i)
        if (dyn_tags[i].tag == tag)
            return dyn_tags[i].name;
    return "UNKNOWN";
}

/**
 * Esta es la primera funcion que debe usarse al cargar un ELF. Comprueba que el ELF
 * tengas los numeros magicos adecuados.
 *
 * @param hdr puntero a una estructura donde se debe contener la informacion cargada de un ELF
 * @return se devuelve true si es un ELF valido o false en caso de no serlo.
 */
bool elf_check_file(Elf32_Header *hdr) {
    if(!hdr) return false;
    if(hdr->e_ident[EI_MAG0] != ELFMAG0) {
        ERROR_ELF("ELF Header EI_MAG0 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG1] != ELFMAG1) {
        ERROR_ELF("ELF Header EI_MAG1 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG2] != ELFMAG2) {
        ERROR_ELF("ELF Header EI_MAG2 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG3] != ELFMAG3) {
        ERROR_ELF("ELF Header EI_MAG3 incorrect.\n");
        return false;
    }
    return true;
}

/**
 * Esta es la segunda funcion a ejecutar para comprobar si un ELF es valido.
 *
 * @param hdr puntero a una estructura donde se debe contener la informacion cargada de un ELF
 * @return se devuelve un true si es un archivo valido, o false si no lo es.
 */
bool elf32_check_supported(Elf32_Header *hdr) {
    if(!elf_check_file(hdr)) {
        ERROR_ELF("Invalid ELF32 File.\n");
        return false;
    }
    if(hdr->e_ident[EI_CLASS] != ELFCLASS32) {
        ERROR_ELF("Unsupported ELF32 File Class.\n");
        return false;
    }
    if(hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        ERROR_ELF("Unsupported ELF32 File byte order.\n");
        return false;
    }
    if(hdr->e_machine != EM_386) {
        ERROR_ELF("Unsupported ELF32 File target.\n");
        return false;
    }
    if(hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        ERROR_ELF("Unsupported ELF32 File version.\n");
        return false;
    }
    if(hdr->e_type != ET_REL && hdr->e_type != ET_EXEC) {
        ERROR_ELF("Unsupported ELF32 File type.\n");
        return false;
    }
    return true;
}
bool elf64_check_supported(Elf64_Header *hdr) {
    if(!elf_check_file((Elf32_Header*)hdr)) {
        ERROR_ELF("Invalid ELF File.\n");
        return false;
    }
    if(hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        ERROR_ELF("Unsupported ELF64 File Class.\n");
        return false;
    }
    if(hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        ERROR_ELF("Unsupported ELF64 File byte order.\n");
        return false;
    }
    if(hdr->e_machine != EM_X86_64) {
        ERROR_ELF("Unsupported ELF64 File target.\n");
        return false;
    }
    if(hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        ERROR_ELF("Unsupported ELF64 File version.\n");
        return false;
    }
    if(hdr->e_type != ET_REL && hdr->e_type != ET_EXEC) {
        ERROR_ELF("Unsupported ELF64 File type.\n");
        return false;
    }
    return true;
}
void *elf32_load_file(void *file) {
    Elf32_Header *hdr = (Elf32_Header *)file;
    if(!elf32_check_supported(hdr)) {
        ERROR_ELF("ELF File cannot be loaded.\n");
        return;
    }
    switch(hdr->e_type) {
        case ET_EXEC:
            // TODO : Implement
            return NULL;
        case ET_REL:
            return elf32_load_rel(hdr);
    }
    return NULL;
}

/**
 *
 * Acceso al valor de un simbolo
 * Algunas operaciones, como la vinculacion y la reubicacion,
 * requieren el valor de un simbolo (o, mejor dicho, su direccion).
 * Aunque las entradas de la tabla de simbolos definen un campo st_value,
 * este solo puede contener una direccion relativa. A continuacion, se
 * muestra un ejemplo de como calcular la direccion absoluta del
 * valor del simbolo. El codigo se ha dividido en
 * varias secciones más pequeñas para facilitar su comprension. (1)
 *
 * El ejemplo anterior realiza una comprobacion tanto con el indice de la tabla
 * de simbolos como con el indice del simbolo; si alguno no está definido,
 * se devuelve 0. En caso contrario, se accede a la entrada del encabezado
 * de seccion de la tabla de simbolos en el indice dado. A continuacion, se
 * comprueba que el indice de la tabla de simbolos no esté fuera de los
 * limites de la tabla de simbolos. Si la comprobacion falla, se muestra
 * un mensaje de error y se devuelve un codigo de error; de lo contrario,
 * se recupera la entrada de la tabla de simbolos en el indice dado. (2)
 *
 * Si la seccion a la que el simbolo es relativo (dada por st_shndx) es
 * igual a SHN_UNDEF, el simbolo es externo y debe estar vinculado a su
 * definicion. Se recupera la tabla de cadenas de la tabla de simbolos
 * actual (la tabla de cadenas de una tabla de simbolos dada está disponible
 * en el encabezado de la seccion de la tabla en sh_link), y el nombre del
 * simbolo se encuentra en la tabla de cadenas. A continuacion, se utiliza
 * la funcion elf_lookup_symbol() para buscar la definicion de un simbolo
 * por nombre (esta funcion no se proporciona; una implementacion minima
 * siempre devuelve NULL). Si se encuentra la definicion del simbolo, se
 * devuelve. Si el simbolo tiene el indicador STB_WEAK (es un simbolo
 * débil), se devuelve 0; de lo contrario, se muestra un mensaje
 * de error y se devuelve un codigo de error. (3)
 *
 * Si el valor de sh_ndx es igual a SHN_ABS, el valor del simbolo es
 * absoluto y se devuelve inmediatamente. Si sh_ndx no contiene un
 * valor especial, significa que el simbolo está definido en el
 * objeto ELF local. Dado que el valor dado por sh_value es
 * relativo a una seccion definida sh_ndx, se accede a la
 * entrada del encabezado de seccion relevante y se calcula
 * la direccion del simbolo sumando la direccion del archivo
 * en la memoria al valor del simbolo con su desplazamiento de seccion.
 *
 * @param hdr
 * @param table
 * @param idx
 * @return
 */
int elf32_get_symval(Elf32_Header *hdr, int table, size_t idx) {
    /* ------------------------------ (1) ------------------------------- */
    if(table == SHN_UNDEF || idx == SHN_UNDEF) return 0;
    Elf32_Shdr *symtab = elf32_section(hdr, table);

    uint32_t symtab_entries = symtab->sh_size / symtab->sh_entsize;
    if(idx >= symtab_entries) {
        ERROR_ELF("Symbol Index out of Range (%d:%u).\n", table, idx);
        return ELF_RELOC_ERR;
    }

    int symaddr = (int)hdr + symtab->sh_offset;
    Elf32_Sym *symbol = &((Elf32_Sym *)symaddr)[idx];
    /* ------------------------------ (1) ------------------------------- */

    /* ------------------------------ (2) ------------------------------- */
    if(symbol->st_shndx == SHN_UNDEF) {
        // Simbolo externo, lookup value
        Elf32_Shdr *strtab = elf32_section(hdr, symtab->sh_link);
        const char *name = (const char *)hdr + strtab->sh_offset + symbol->st_name;

        void *target = elf_lookup_symbol(name);

        if(target == NULL) {
            // simbolo externo no encontrado
            if(ELF32_ST_BIND(symbol->st_info) & STB_WEAK) {
                // Weak symbol initialized as 0
                return 0;
            } else {
                ERROR_ELF("Simbolo externo no definido : %s.\n", name);
                return ELF_RELOC_ERR;
            }
        } else {
            return (int)target;
        }
        /* ------------------------------ (2) ------------------------------- */

        /* ------------------------------ (3) ------------------------------- */
    } else if(symbol->st_shndx == SHN_ABS) {
        // Simbolo absoluto
        return symbol->st_value;
    } else {
        // definicion de simbolo interno
        Elf32_Shdr *target = elf32_section(hdr, symbol->st_shndx);
        return (int)hdr + symbol->st_value + target->sh_offset;
    }
    /* ------------------------------ (3) ------------------------------- */
}

/**
 * El BSS y SHT_NOBITS
 * El BSS (la seccion denominada ".bss") es, en su forma más simple,
 * un bloque de memoria que se ha puesto a cero.
 * El BSS es el área de memoria donde se almacenan las variables con un tiempo de
 * vida global que no se han inicializado (o que se han inicializado a 0 o NULL).
 *
 * El encabezado de seccion del BSS define su tipo sh_type como SHT_NOBITS,
 * lo que significa que no está presente en la imagen de archivo y debe
 * asignarse durante la ejecucion. Una forma sencilla e intuitiva de
 * asignar un BSS es asignar memoria y ponerla a cero con un conjunto
 * de memoria (memset). No poner a cero el BSS puede causar un
 * comportamiento inesperado en cualquier programa cargado.
 *
 * Además, es importante tener en cuenta que el BSS debe asignarse
 * antes de realizar cualquier operacion que dependa del direccionamiento
 * relativo (como la reubicacion), ya que de lo contrario el codigo
 * puede referenciar memoria basura o generar un fallo.
 *
 * Si bien el BSS es un ejemplo especifico, cualquier seccion de tipo
 * SHT_NOBITS con el atributo SHF_ALLOC debe asignarse al inicio de
 * la carga del programa.
 *
 * Dado que este tutorial es general y no especifico, el siguiente ejemplo
 * seguirá la tendencia y utilizará el ejemplo más simple para la
 * asignacion de secciones.
 *
 * @param hdr
 * @return
 */
int elf32_load_stage1(Elf32_Header *hdr) {
    /**
     * El ejemplo anterior asigna la memoria necesaria para la seccion,
     * descrita por el campo sh_size del encabezado de la seccion. Aunque
     * la funcion del ejemplo solo busca las secciones que deben asignarse,
     * puede modificarse para realizar otras operaciones que deben
     * realizarse al principio del proceso de carga.
     */
    Elf32_Shdr *shdr = elf32_sheader(hdr);

    unsigned int i;
    // Iterate over section headers
    for(i = 0; i < hdr->e_shnum; i++) {
        Elf32_Shdr *section = &shdr[i];

        // If the section isn't present in the file
        if(section->sh_type == SHT_NOBITS) {
            // Skip if it the section is empty
            if(!section->sh_size) continue;
            // If the section should appear in memory
            if(section->sh_flags & SHF_ALLOC) {
                // Allocate and zero some memory
                void *mem = malloc(section->sh_size);
                memset(mem, 0, section->sh_size);

                // Assign the memory offset to the section offset
                section->sh_offset = (int)mem - (int)hdr;
                DEBUG("Allocated memory for a section (%ld).\n", section->sh_size);
            }
        }
    }
    return 0;
}

/**
 * Ejemplo de reubicacion
 * Cargar un archivo ELF reubicable implica procesar todas las entradas
 * de reubicacion presentes en el archivo (¡Recuerde asignar primero todas las
 * secciones SHT_NOBITS!). Este proceso comienza con la búsqueda de todas las
 * tablas de reubicacion en el archivo, como se muestra en el codigo de ejemplo a
 * continuacion.
 *
 * @param hdr
 * @return
 */
int elf32_load_stage2(Elf32_Header *hdr) {
    /**
     * Tenga en cuenta que el codigo solo procesa entradas Elf32_Rel, pero puede
     * modificarse para procesar también entradas con sumandos explicitos.
     * El codigo también se basa en una funcion llamada elf_do_reloc,
     * que se mostrará en el siguiente ejemplo.
     *
     * Esta funcion de ejemplo se detiene, muestra un mensaje de error y
     * devuelve un codigo de error si no puede procesar una reubicacion.
     */
    Elf32_Shdr *shdr = elf32_sheader(hdr);

    unsigned int i, idx;
    // Iterate over section headers
    for(i = 0; i < hdr->e_shnum; i++) {
        Elf32_Shdr *section = &shdr[i];

        // If this is a relocation section
        if(section->sh_type == SHT_REL) {
            // Process each entry in the table
            for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
                Elf32_Rel *reltab = &((Elf32_Rel *)((int)hdr + section->sh_offset))[idx];
                int result = elf32_do_reloc(hdr, reltab, section);
                // On error, display a message and return
                if(result == ELF_RELOC_ERR) {
                    ERROR_ELF("Failed to relocate symbol.\n");
                    return ELF_RELOC_ERR;
                }
            }
        }
    }
    return 0;
}

/**
 * Dado que la siguiente funcion es bastante compleja, se ha dividido en fragmentos
 * más pequeños y fáciles de manejar, y se ha explicado en detalle.
 *
 * Tenga en cuenta que el codigo a continuacion asume que el archivo que se
 * reubica es un archivo ELF reubicable (los ejecutables ELF y los objetos compartidos
 * también pueden contener entradas de reubicacion, pero se procesan de forma
 * ligeramente diferente).
 *
 * Tenga en cuenta también que sh_info, para los encabezados de
 * seccion de tipo SHT_REL y SHT_RELA, almacena el encabezado de seccion
 * al que se aplica la reubicacion. (1)
 *
 * #define DO_386_32(S, A)	    ((S) + (A))
 * #define DO_386_PC32(S, A, P)	((S) + (A) - (P))
 *
 * El codigo anterior define las macrofunciones que se utilizan para
 * realizar los cálculos de reubicacion. También recupera el
 * encabezado de la seccion donde se encuentra el simbolo y
 * calcula una referencia a este. La variable addr indica el inicio
 * de la seccion del simbolo, y ref se crea sumando el desplazamiento
 * del simbolo desde la entrada de reubicacion. (2)
 *
 * A continuacion, se accede al valor del simbolo que se está reubicando.
 * Si el indice de la tabla de simbolos almacenado en r_info no está
 * definido, el valor predeterminado es 0. El codigo también hace
 * referencia a una funcion llamada elf_get_symval(), implementada
 * previamente. Si el valor devuelto por la funcion es igual a
 * ELF_RELOC_ERR, se detiene la reubicacion y se devuelve dicho
 * codigo de error. (3)
 *
 * Finalmente, este segmento de codigo detalla el proceso de reubicacion,
 * realizando el cálculo necesario del simbolo reubicado y devolviendo su
 * valor en caso de éxito. Si el tipo de reubicacion no es compatible,
 * se muestra un mensaje de error, se detiene la reubicacion y la funcion
 * devuelve un codigo de error. Si no se han producido errores,
 * la reubicacion está completa.
 *
 * @param hdr
 * @param rel
 * @param reltab
 * @return
 */
int elf32_do_reloc(Elf32_Header *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab) {
    /* ------------------------------ (1) ------------------------------- */
    Elf32_Shdr *target = elf32_section(hdr, reltab->sh_info);

    int addr = (int)hdr + target->sh_offset;
    int *ref = (int *)(addr + rel->r_offset);
    /* ------------------------------ (1) ------------------------------- */

    /* ------------------------------ (2) ------------------------------- */
    // Symbol value
    int symval = 0;
    if(ELF32_R_SYM(rel->r_info) != SHN_UNDEF) {
        symval = elf32_get_symval(hdr, reltab->sh_link, ELF32_R_SYM(rel->r_info));
        if(symval == ELF_RELOC_ERR) return ELF_RELOC_ERR;
    }
    /* ------------------------------ (2) ------------------------------- */

    /* ------------------------------ (3) ------------------------------- */
    // Relocate based on type
    switch(ELF32_R_TYPE(rel->r_info)) {
        case R_386_NONE:
            // No relocation
            break;
        case R_386_32:
            // Symbol + Offset
            *ref = DO_386_32(symval, *ref);
            break;
        case R_386_PC32:
            // Symbol + Offset - Section Offset
            *ref = DO_386_PC32(symval, *ref, (int)ref);
            break;
        default:
            // Relocation type not supported, display error and return
            ERROR_ELF("Unsupported Relocation Type (%d).\n", ELF32_R_TYPE(rel->r_info));
            return ELF_RELOC_ERR;
    }
    return symval;
    /* ------------------------------ (3) ------------------------------- */
}


/**
 * El encabezado del programa es una estructura que define informacion
 * sobre el comportamiento del programa ELF una vez cargado, asi como
 * informacion de enlace en tiempo de ejecucion. Los encabezados de programa
 * ELF (al igual que los encabezados de seccion) se agrupan para formar la
 * tabla de encabezados de programa.
 *
 * La tabla de encabezados de programa contiene un conjunto continuo de
 * encabezados de programa (por lo tanto, se puede acceder a ellos como
 * si fueran una matriz). Se puede acceder a la tabla mediante el campo
 * e_phoff definido en el encabezado ELF, siempre que esté presente.
 *
 * El encabezado define varios campos útiles como p_type,
 * que distingue entre encabezados; p_offset, que almacena el
 * desplazamiento hasta el segmento al que se refiere el encabezado;
 * y p_vaddr, que define la direccion donde debe existir el codigo
 * dependiente de la posicion.
 *
 * @param mem es la ubicacion del encabezado ELF
 */
void *elf32_load_segment_to_memory(void *mem, Elf64_Phdr *phdr, int elf_fd) {
    size_t mem_size = phdr->p_memsz;
    off_t mem_offset = phdr->p_offset;
    size_t file_size = phdr->p_filesz;
    void *vaddr = (void *)(phdr->p_vaddr);
    // mmap the memory region with the correct protections
    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    off_t page_offset = (uint64_t)vaddr % PAGE_SIZE;
    void *aligned_vaddr = (void *)((uint64_t)vaddr - page_offset);
    size_t aligned_size = mem_size + page_offset;

    int flags = MAP_PRIVATE_ | MAP_ANONYMOUS_;
    map_segment(
        aligned_vaddr,
        file_size + page_offset,
        prot,
        flags,
        elf_fd,
        mem_offset - page_offset
        );
    // technically we can just have vaddr as the first argument as mmap will
    // automatically truncate to the start of the page
    if (mem_size > file_size) {
        void *page_break = (void*)(((uint64_t)vaddr + mem_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

        memset((uint64_t)vaddr + file_size, 0, (uint64_t)page_break - (uint64_t)vaddr - file_size);
        if (mem_size > (uint64_t)page_break - (uint64_t)vaddr) {
            map_segment(
                page_break,
                mem_size - ((uint64_t)page_break - (uint64_t)vaddr),
                prot,
                flags,
                -1,
                0
                );
            memset(page_break, 0, mem_size - ((uint64_t)page_break - (uint64_t)vaddr));

        }
    }
    return vaddr;
}

bool elf_mem_parse(ElfFile *elf, void *mem, size_t size) {
    if (!mem || size < 16) return false;
    uint8_t *e_ident = (uint8_t *)mem;
    if (e_ident[EI_MAG0]!=ELFMAG0 || e_ident[EI_MAG1]!=ELFMAG1 ||
        e_ident[EI_MAG2]!=ELFMAG2 || e_ident[EI_MAG3]!=ELFMAG3)
        return false;
    elf->mem = mem;
    elf->size = size;
    if (e_ident[EI_CLASS] == ELFCLASS32) {
        elf->elf_class = ELFCLASS_32;
        elf->ehdr32 = (Elf32_Header *)mem;
    } else if (e_ident[EI_CLASS] == ELFCLASS64) {
        elf->elf_class = ELFCLASS_64;
        elf->ehdr64 = (Elf64_Header *)mem;
    } else {
        elf->elf_class = ELFCLASS_UNKNOWN;
        return false;
    }
    return true;
}

size_t elf_section_count(const ElfFile *elf) {
    return (elf->elf_class==ELFCLASS_32) ? elf->ehdr32->e_shnum : elf->ehdr64->e_shnum;
}
const char *elf_section_name(const ElfFile *elf, size_t idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        Elf32_Shdr *strtab = &shdr[elf->ehdr32->e_shstrndx];
        return (const char *)elf->mem + strtab->sh_offset + shdr[idx].sh_name;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        Elf64_Shdr *strtab = &shdr[elf->ehdr64->e_shstrndx];
        return (const char *)elf->mem + strtab->sh_offset + shdr[idx].sh_name;
    }
}
uint32_t elf_section_type(const ElfFile *elf, size_t idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        return shdr[idx].sh_type;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        return shdr[idx].sh_type;
    }
}
uint64_t elf_section_addr(const ElfFile *elf, size_t idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        return shdr[idx].sh_addr;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        return shdr[idx].sh_addr;
    }
}
uint64_t elf_section_offset(const ElfFile *elf, size_t idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        return shdr[idx].sh_offset;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        return shdr[idx].sh_offset;
    }
}
uint64_t elf_section_size(const ElfFile *elf, size_t idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        return shdr[idx].sh_size;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        return shdr[idx].sh_size;
    }
}

// --- Simbolos ---
size_t elf_symbol_count(const ElfFile *elf, size_t *symtab_idx) {
    size_t n = elf_section_count(elf);
    for (size_t i=0; i<n; ++i) {
        if (elf_section_type(elf, i)==SHT_SYMTAB) {
            if (symtab_idx) *symtab_idx = i;
            uint64_t entsize = elf_section_size(elf, i);
            uint64_t size = elf_section_size(elf, i);
            return entsize ? size / entsize : 0;
        }
    }
    if (symtab_idx) *symtab_idx = (size_t)-1;
    return 0;
}
const char *elf_symbol_name(const ElfFile *elf, size_t symtab_idx, size_t sym_idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        Elf32_Shdr *symtab = &shdr[symtab_idx];
        Elf32_Shdr *strtab = &shdr[symtab->sh_link];
        Elf32_Sym *syms = (Elf32_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return (const char *)elf->mem + strtab->sh_offset + syms[sym_idx].st_name;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        Elf64_Shdr *symtab = &shdr[symtab_idx];
        Elf64_Shdr *strtab = &shdr[symtab->sh_link];
        Elf64_Sym *syms = (Elf64_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return (const char *)elf->mem + strtab->sh_offset + syms[sym_idx].st_name;
    }
}
uint64_t elf_symbol_value(const ElfFile *elf, size_t symtab_idx, size_t sym_idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        Elf32_Shdr *symtab = &shdr[symtab_idx];
        Elf32_Sym *syms = (Elf32_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return syms[sym_idx].st_value;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        Elf64_Shdr *symtab = &shdr[symtab_idx];
        Elf64_Sym *syms = (Elf64_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return syms[sym_idx].st_value;
    }
}
uint8_t elf_symbol_info(const ElfFile *elf, size_t symtab_idx, size_t sym_idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        Elf32_Shdr *symtab = &shdr[symtab_idx];
        Elf32_Sym *syms = (Elf32_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return syms[sym_idx].st_info;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        Elf64_Shdr *symtab = &shdr[symtab_idx];
        Elf64_Sym *syms = (Elf64_Sym *)((uint8_t *)elf->mem + symtab->sh_offset);
        return syms[sym_idx].st_info;
    }
}

// --- Relocaciones ---
size_t elf_relocation_count(const ElfFile *elf, size_t rel_idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        return shdr[rel_idx].sh_size / shdr[rel_idx].sh_entsize;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        return shdr[rel_idx].sh_size / shdr[rel_idx].sh_entsize;
    }
}
void elf_get_relocation(const ElfFile *elf, size_t rel_idx, size_t rel_ent,
                        uint64_t *offset, uint32_t *type, int *sym_idx) {
    if (elf->elf_class==ELFCLASS_32) {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
        Elf32_Rel *rels = (Elf32_Rel *)((uint8_t *)elf->mem + shdr[rel_idx].sh_offset);
        *offset = rels[rel_ent].r_offset;
        *type = rels[rel_ent].r_info & 0xff;
        *sym_idx = rels[rel_ent].r_info >> 8;
    } else {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
        Elf64_Rel *rels = (Elf64_Rel *)((uint8_t *)elf->mem + shdr[rel_idx].sh_offset);
        *offset = rels[rel_ent].r_offset;
        *type = rels[rel_ent].r_info & 0xffffffff;
        *sym_idx = rels[rel_ent].r_info >> 32;
    }
}

// --- Librerias requeridas (DT_NEEDED) ---
size_t elf_needed_count(const ElfFile *elf) {
    // Busca SHT_DYNAMIC y cuenta DT_NEEDED
    size_t n = elf_section_count(elf), count=0;
    for (size_t i=0; i<n; ++i) {
        if (elf_section_type(elf, i)==SHT_DYNAMIC) { // SHT_DYNAMIC
            if (elf->elf_class==ELFCLASS_32) {
                Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
                Elf32_Dyn *dyn = (Elf32_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                size_t nent = shdr[i].sh_size/sizeof(Elf32_Dyn);
                for (size_t j=0; j<nent; ++j) if (dyn[j].d_tag==1) ++count;
            } else {
                Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
                Elf64_Dyn *dyn = (Elf64_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                size_t nent = shdr[i].sh_size/sizeof(Elf64_Dyn);
                for (size_t j=0; j<nent; ++j) if (dyn[j].d_tag==1) ++count;
            }
        }
    }
    return count;
}
const char *elf_needed_name(const ElfFile *elf, size_t idx) {
    // Busca SHT_DYNAMIC y devuelve el nombre idx-ésimo DT_NEEDED
    size_t n = elf_section_count(elf), count=0;
    for (size_t i=0; i<n; ++i) {
        if (elf_section_type(elf, i)==SHT_DYNAMIC) { // SHT_DYNAMIC
            if (elf->elf_class==ELFCLASS_32) {
                Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
                Elf32_Dyn *dyn = (Elf32_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                Elf32_Shdr *strtab = NULL;
                for (size_t j=0; j<n; ++j)
                    if (elf_section_type(elf, j)==3 && strcmp(elf_section_name(elf, j), ".dynstr")==0)
                        strtab = &shdr[j];
                if (!strtab) continue;
                const char *base = (const char *)elf->mem + strtab->sh_offset;
                size_t nent = shdr[i].sh_size/sizeof(Elf32_Dyn);
                for (size_t j=0; j<nent; ++j) {
                    if (dyn[j].d_tag==1) {
                        if (count==idx) return base + dyn[j].d_un.d_val;
                        ++count;
                    }
                }
            } else {
                Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
                Elf64_Dyn *dyn = (Elf64_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                Elf64_Shdr *strtab = NULL;
                for (size_t j=0; j<n; ++j)
                    if (elf_section_type(elf, j)==3 && strcmp(elf_section_name(elf, j), ".dynstr")==0)
                        strtab = &shdr[j];
                if (!strtab) continue;
                const char *base = (const char *)elf->mem + strtab->sh_offset;
                size_t nent = shdr[i].sh_size/sizeof(Elf64_Dyn);
                for (size_t j=0; j<nent; ++j) {
                    if (dyn[j].d_tag==1) {
                        if (count==idx) return base + dyn[j].d_un.d_val;
                        ++count;
                    }
                }
            }
        }
    }
    return NULL;
}

// --- Strings ---
void elf_iterate_strings(const ElfFile *elf, void (*cb)(const char *str, void *user), void *user) {
    size_t n = elf_section_count(elf);
    for (size_t i=0; i<n; ++i) {
        if (elf_section_type(elf, i)==SHT_STRTAB) {
            const char *base = (const char *)elf->mem + elf_section_offset(elf, i);
            size_t size = elf_section_size(elf, i), j=0;
            while (j<size) {
                if (base[j]) {
                    cb(&base[j], user);
                    j += strlen(&base[j]);
                }
                ++j;
            }
        }
    }
}


// --- Mostrar informacion de la cabecera ELF ---
void show_elf_header(const ElfFile *elf) {
    if (elf->elf_class == ELFCLASS_32) {
        Elf32_Header *h = elf->ehdr32;
        printf("ELF Header:\n");
        printf("  Ident: ");
        for (int i = 0; i < 16; ++i) printf("%02x ", h->e_ident[i]);
        printf("\n  Tipo: %u\n  Máquina: %u\n  Version: %u\n", h->e_type, h->e_machine, h->e_version);
        printf("  Entry: 0x%08x\n", h->e_entry);
        printf("  PHoff: 0x%08x  SHoff: 0x%08x\n", h->e_phoff, h->e_shoff);
        printf("  Flags: 0x%08x\n", h->e_flags);
        printf("  EHsize: %u  PHentsize: %u  PHnum: %u\n", h->e_ehsize, h->e_phentsize, h->e_phnum);
        printf("  SHentsize: %u  SHnum: %u  SHstrndx: %u\n", h->e_shentsize, h->e_shnum, h->e_shstrndx);
    } else {
        Elf64_Header *h = elf->ehdr64;
        printf("ELF Header:\n");
        printf("  Ident: ");
        for (int i = 0; i < 16; ++i) printf("%02x ", h->e_ident[i]);
        printf("\n  Tipo: %u\n  Máquina: %u\n  Version: %u\n", h->e_type, h->e_machine, h->e_version);
        printf("  Entry: 0x%016" PRIx64 "\n", (uint64_t)h->e_entry);
        printf("  PHoff: 0x%016" PRIx64 "  SHoff: 0x%016" PRIx64 "\n", (uint64_t)h->e_phoff, (uint64_t)h->e_shoff);
        printf("  Flags: 0x%08x\n", h->e_flags);
        printf("  EHsize: %u  PHentsize: %u  PHnum: %u\n", h->e_ehsize, h->e_phentsize, h->e_phnum);
        printf("  SHentsize: %u  SHnum: %u  SHstrndx: %u\n", h->e_shentsize, h->e_shnum, h->e_shstrndx);
    }
}

// --- Mostrar cabecera de programa ---
void show_elf_program_headers(const ElfFile *elf) {
    printf("\nProgram Headers:\n");
    if (elf->elf_class == ELFCLASS_32) {
        Elf32_Header *h = elf->ehdr32;
        Elf32_Phdr *phdr = (Elf32_Phdr *)((uint8_t *)elf->mem + h->e_phoff);
        for (int i = 0; i < h->e_phnum; ++i) {
            printf("  %2d: Type: 0x%x Offset: 0x%08x Vaddr: 0x%08x Paddr: 0x%08x Filesz: 0x%08x Memsz: 0x%08x Flags: 0x%x Align: 0x%x\n",
                i, phdr[i].p_type, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr,
                phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_flags, phdr[i].p_align);
        }
    } else {
        Elf64_Header *h = elf->ehdr64;
        Elf64_Phdr *phdr = (Elf64_Phdr *)((uint8_t *)elf->mem + h->e_phoff);
        for (int i = 0; i < h->e_phnum; ++i) {
            printf("  %2d: Type: 0x%x Offset: 0x%016" PRIx64 " Vaddr: 0x%016" PRIx64 " Paddr: 0x%016" PRIx64 " Filesz: 0x%016" PRIx64 " Memsz: 0x%016" PRIx64 " Flags: 0x%x Align: 0x%" PRIx64 "\n",
                i, phdr[i].p_type, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr,
                phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_flags, phdr[i].p_align);
        }
    }
}

// --- Mostrar tabla dinámica (DT_*) ---
void show_elf_dynamic(const ElfFile *elf) {
    printf("\nDynamic Section (detallada):\n");
    size_t n = elf_section_count(elf);
    for (size_t i=0; i<n; ++i) {
        if (elf_section_type(elf, i) == SHT_DYNAMIC) {
            // Busca la string table asociada
            const char *strtab = NULL;
            if (elf->elf_class == ELFCLASS_32) {
                Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
                for (size_t j=0; j<n; ++j)
                    if (elf_section_type(elf, j) == SHT_STRTAB && strcmp(elf_section_name(elf, j), ".dynstr") == 0)
                        strtab = (const char *)elf->mem + shdr[j].sh_offset;
                Elf32_Dyn *dyn = (Elf32_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                size_t nent = shdr[i].sh_size / sizeof(Elf32_Dyn);
                for (size_t j=0; j<nent; ++j) {
                    uint32_t tag = dyn[j].d_tag;
                    uint32_t val = dyn[j].d_un.d_val;
                    const char *tagname = dyn_tag_name(tag);
                    printf("  Tag: 0x%08x (%-14s)  Val: 0x%08x", tag, tagname, val);
                    // Mostrar string asociado si corresponde
                    if ((tag == 1 || tag == 14 || tag == 15 || tag == 29) && strtab && val)
                        printf("  String: '%s'", strtab + val);
                    printf("\n");
                }
            } else {
                Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
                for (size_t j=0; j<n; ++j)
                    if (elf_section_type(elf, j) == SHT_STRTAB && strcmp(elf_section_name(elf, j), ".dynstr") == 0)
                        strtab = (const char *)elf->mem + shdr[j].sh_offset;
                Elf64_Dyn *dyn = (Elf64_Dyn *)((uint8_t *)elf->mem + shdr[i].sh_offset);
                size_t nent = shdr[i].sh_size / sizeof(Elf64_Dyn);
                for (size_t j=0; j<nent; ++j) {
                    uint64_t tag = dyn[j].d_tag;
                    uint64_t val = dyn[j].d_un.d_val;
                    const char *tagname = dyn_tag_name(tag);
                    printf("  Tag: 0x%016" PRIx64 " (%-14s)  Val: 0x%016" PRIx64, tag, tagname, val);
                    // Mostrar string asociado si corresponde
                    if ((tag == 1 || tag == 14 || tag == 15 || tag == 29) && strtab && val)
                        printf("  String: '%s'", strtab + val);
                    printf("\n");
                }
            }
        }
    }
}


// --- Mostrar notas (si existen) ---

// Muestra todas las notas de todas las secciones SHT_NOTE
void show_elf_notes(const ElfFile *elf) {
    printf("\nNotes (detalladas):\n");
    for (size_t i = 0; i < elf_section_count(elf); ++i) {
        if (elf_section_type(elf, i) == SHT_NOTE) {
            const char *secname = elf_section_name(elf, i);
            uint64_t offset = elf_section_offset(elf, i);
            uint64_t size   = elf_section_size(elf, i);
            const uint8_t *data = (const uint8_t *)elf->mem + offset;
            printf("  Seccion %zu: %s (offset 0x%lx, size 0x%lx)\n", i, secname, (unsigned long)offset, (unsigned long)size);

            size_t pos = 0;
            while (pos + 12 <= size) { // Cabecera de nota: 3 x 4 bytes (32 bits)
                uint32_t namesz, descsz, type;
                if (elf->elf_class == ELFCLASS_32) {
                    namesz = *(uint32_t *)(data + pos);
                    descsz = *(uint32_t *)(data + pos + 4);
                    type   = *(uint32_t *)(data + pos + 8);
                    pos += 12;
                } else {
                    namesz = *(uint32_t *)(data + pos);
                    descsz = *(uint32_t *)(data + pos + 4);
                    type   = *(uint32_t *)(data + pos + 8);
                    pos += 12;
                }
                // El nombre del propietario
                const char *name = (const char *)(data + pos);
                printf("    Owner: '%.*s'  Type: 0x%x  NameSz: %u  DescSz: %u\n",
                       namesz, name, type, namesz, descsz);
                // Avanza a la descripcion (alineada a 4 bytes)
                pos += ((namesz + 3) & ~3);
                // La descripcion
                const uint8_t *desc = data + pos;
                if (strcmp(name, "GNU") == 0 && type == 3 && descsz >= 16) {
                    // Build-ID
                    printf("      GNU Build-ID: ");
                    print_hex(desc, descsz);
                } else if (strcmp(name, "GNU") == 0 && type == 1 && descsz >= 16) {
                    // ABI tag
                    if (descsz >= 16) {
                        uint32_t os = *(uint32_t *)desc;
                        uint32_t abi_major = *(uint32_t *)(desc + 4);
                        uint32_t abi_minor = *(uint32_t *)(desc + 8);
                        uint32_t abi_patch = *(uint32_t *)(desc + 12);
                        printf("      GNU ABI: OS=%u, ABI=%u.%u.%u\n", os, abi_major, abi_minor, abi_patch);
                    }
                } else if (strcmp(name, "GNU") == 0 && type == 5) {
                    // .note.gnu.property (puede contener propiedades de seguridad, etc.)
                    printf("      GNU Property (hex): ");
                    print_hex(desc, descsz);
                } else {
                    printf("      Desc (hex): ");
                    print_hex(desc, descsz);
                }
                pos += ((descsz + 3) & ~3);
            }
        }
    }
}


// Imprime un dump hexadecimal y ASCII de una seccion
void print_section_dump(const uint8_t *data, size_t size, uint64_t addr) {
    for (size_t i = 0; i < size; i += 16) {
        printf("  %08lx: ", (unsigned long)(addr + i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

// Muestra el contenido de las secciones de codigo y datos

// Muestra el contenido de las secciones de codigo y datos
void show_elf_code_data_sections(const ElfFile *elf) {
    printf("\nContenido de secciones de codigo y datos:\n");
    for (size_t i = 0; i < elf_section_count(elf); ++i) {
        uint32_t type = elf_section_type(elf, i);
        uint64_t size = elf_section_size(elf, i);
        uint64_t offset = elf_section_offset(elf, i);
        uint64_t addr = elf_section_addr(elf, i);
        const char *name = elf_section_name(elf, i);

        // Solo secciones con datos en el archivo (no SHT_NOBITS)
        // y que sean tipicamente codigo o datos
        if (type != SHT_NOBITS && size > 0 &&
            (strcmp(name, ".text") == 0 ||
             strcmp(name, ".data") == 0 ||
             strcmp(name, ".rodata") == 0 ||
             strcmp(name, ".init") == 0 ||
             strcmp(name, ".fini") == 0 ||
             strcmp(name, ".plt") == 0 ||
             strcmp(name, ".got") == 0 ||
             strcmp(name, ".got.plt") == 0)) {
            printf("Seccion %zu: %s (offset 0x%lx, size 0x%lx, addr 0x%lx)\n",
                   i, name, (unsigned long)offset, (unsigned long)size, (unsigned long)addr);
            const uint8_t *data = (const uint8_t *)elf->mem + offset;
            print_section_dump(data, size, addr);
             }
    }
}


void show_elf_code_data_sections_auto(const ElfFile *elf) {
    printf("\nContenido de secciones de codigo y datos (auto):\n");
    for (size_t i = 0; i < elf_section_count(elf); ++i) {
        uint32_t type = elf_section_type(elf, i);
        uint64_t size = elf_section_size(elf, i);
        uint64_t offset = elf_section_offset(elf, i);
        uint64_t addr = elf_section_addr(elf, i);
        const char *name = elf_section_name(elf, i);

        if (type != SHT_NOBITS && size > 0) {
            uint64_t flags = 0;
            if (elf->elf_class == ELFCLASS_32) {
                Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)elf->mem + elf->ehdr32->e_shoff);
                flags = shdr[i].sh_flags;
            } else {
                Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)elf->mem + elf->ehdr64->e_shoff);
                flags = shdr[i].sh_flags;
            }
            if (flags & SHF_ALLOC) { // Está en memoria
                printf("Seccion %zu: %-16s (offset 0x%lx, size 0x%lx, addr 0x%lx, flags 0x%lx)%s%s\n",
                       i, name, (unsigned long)offset, (unsigned long)size, (unsigned long)addr, (unsigned long)flags,
                       (flags & SHF_EXECINSTR) ? " [CODE]" : "",
                       (flags & SHF_WRITE) ? " [DATA]" : "");
                const uint8_t *data = (const uint8_t *)elf->mem + offset;
                print_section_dump(data, size, addr);
            }
        }
    }
}


void show_elf_info(const ElfFile *elf) {
    void print_f(const char *s, void *u) {
        printf("  %s\n", s);
    }
    printf("ELF Class: %s\n", elf->elf_class==ELFCLASS_32 ? "ELF32" : "ELF64");
    printf("Secciones:\n");
    for (size_t i=0; i<elf_section_count(elf); ++i) {
        printf("  %2zu: %-20s Tipo: %u Addr: 0x%lx Offset: 0x%lx Size: 0x%lx\n",
            i, elf_section_name(elf, i), elf_section_type(elf, i),
            (unsigned long)elf_section_addr(elf, i),
            (unsigned long)elf_section_offset(elf, i),
            (unsigned long)elf_section_size(elf, i));
    }
    show_elf_code_data_sections_auto(elf);
    size_t symtab_idx;
    size_t nsym = elf_symbol_count(elf, &symtab_idx);
    if (nsym) {
        printf("\nSimbolos:\n");
        for (size_t i=0; i<nsym; ++i) {
            uint8_t info = elf_symbol_info(elf, symtab_idx, i);
            printf("  %3zu: %-30s 0x%lx Info: 0x%02x [%s|%s]\n",
                i, elf_symbol_name(elf, symtab_idx, i),
                (unsigned long)elf_symbol_value(elf, symtab_idx, i),
                info, sym_type_str(info), sym_bind_str(info));
        }
    }
    // Relocaciones extendidas
    printf("\nRelocaciones:\n");
    for (size_t i=0; i<elf_section_count(elf); ++i) {
        if (elf_section_type(elf, i)==SHT_REL || elf_section_type(elf, i)==SHT_RELA) {
            size_t nrel = elf_relocation_count(elf, i);
            for (size_t j=0; j<nrel; ++j) {
                uint64_t off; uint32_t type; int sym;
                elf_get_relocation(elf, i, j, &off, &type, &sym);
                printf("  Seccion %zu Rel %zu: Offset 0x%lx Type %u Sym %d\n", i, j, (unsigned long)off, type, sym);
            }
        }
    }

    // Librerias requeridas
    printf("\nLibrerias requeridas:\n");
    size_t nlib = elf_needed_count(elf);
    for (size_t i=0; i<nlib; ++i)
        printf("  %s\n", elf_needed_name(elf, i));

    printf("\nStrings de tablas de cadenas:\n");
    elf_iterate_strings(elf, print_f, NULL);

    // Dynamic
    show_elf_dynamic(elf);

    // Notas
    show_elf_notes(elf);
}
#endif