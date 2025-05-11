
#ifndef LIB_ELF_PARSE_C
#define LIB_ELF_PARSE_C

#include "LibELFparse.h"

#include <stdatomic.h>

#include "UtilsC.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

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


/**
 *
 * Acceso al valor de un símbolo
 * Algunas operaciones, como la vinculación y la reubicación,
 * requieren el valor de un símbolo (o, mejor dicho, su dirección).
 * Aunque las entradas de la tabla de símbolos definen un campo st_value,
 * este solo puede contener una dirección relativa. A continuación, se
 * muestra un ejemplo de cómo calcular la dirección absoluta del
 * valor del símbolo. El código se ha dividido en
 * varias secciones más pequeñas para facilitar su comprensión. (1)
 *
 * El ejemplo anterior realiza una comprobación tanto con el índice de la tabla
 * de símbolos como con el índice del símbolo; si alguno no está definido,
 * se devuelve 0. En caso contrario, se accede a la entrada del encabezado
 * de sección de la tabla de símbolos en el índice dado. A continuación, se
 * comprueba que el índice de la tabla de símbolos no esté fuera de los
 * límites de la tabla de símbolos. Si la comprobación falla, se muestra
 * un mensaje de error y se devuelve un código de error; de lo contrario,
 * se recupera la entrada de la tabla de símbolos en el índice dado. (2)
 *
 * Si la sección a la que el símbolo es relativo (dada por st_shndx) es
 * igual a SHN_UNDEF, el símbolo es externo y debe estar vinculado a su
 * definición. Se recupera la tabla de cadenas de la tabla de símbolos
 * actual (la tabla de cadenas de una tabla de símbolos dada está disponible
 * en el encabezado de la sección de la tabla en sh_link), y el nombre del
 * símbolo se encuentra en la tabla de cadenas. A continuación, se utiliza
 * la función elf_lookup_symbol() para buscar la definición de un símbolo
 * por nombre (esta función no se proporciona; una implementación mínima
 * siempre devuelve NULL). Si se encuentra la definición del símbolo, se
 * devuelve. Si el símbolo tiene el indicador STB_WEAK (es un símbolo
 * débil), se devuelve 0; de lo contrario, se muestra un mensaje
 * de error y se devuelve un código de error. (3)
 *
 * Si el valor de sh_ndx es igual a SHN_ABS, el valor del símbolo es
 * absoluto y se devuelve inmediatamente. Si sh_ndx no contiene un
 * valor especial, significa que el símbolo está definido en el
 * objeto ELF local. Dado que el valor dado por sh_value es
 * relativo a una sección definida sh_ndx, se accede a la
 * entrada del encabezado de sección relevante y se calcula
 * la dirección del símbolo sumando la dirección del archivo
 * en la memoria al valor del símbolo con su desplazamiento de sección.
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

        extern void *elf_lookup_symbol(const char *name);
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
 * El BSS (la sección denominada ".bss") es, en su forma más simple,
 * un bloque de memoria que se ha puesto a cero.
 * El BSS es el área de memoria donde se almacenan las variables con un tiempo de
 * vida global que no se han inicializado (o que se han inicializado a 0 o NULL).
 *
 * El encabezado de sección del BSS define su tipo sh_type como SHT_NOBITS,
 * lo que significa que no está presente en la imagen de archivo y debe
 * asignarse durante la ejecución. Una forma sencilla e intuitiva de
 * asignar un BSS es asignar memoria y ponerla a cero con un conjunto
 * de memoria (memset). No poner a cero el BSS puede causar un
 * comportamiento inesperado en cualquier programa cargado.
 *
 * Además, es importante tener en cuenta que el BSS debe asignarse
 * antes de realizar cualquier operación que dependa del direccionamiento
 * relativo (como la reubicación), ya que de lo contrario el código
 * puede referenciar memoria basura o generar un fallo.
 *
 * Si bien el BSS es un ejemplo específico, cualquier sección de tipo
 * SHT_NOBITS con el atributo SHF_ALLOC debe asignarse al inicio de
 * la carga del programa.
 *
 * Dado que este tutorial es general y no específico, el siguiente ejemplo
 * seguirá la tendencia y utilizará el ejemplo más simple para la
 * asignación de secciones.
 *
 * @param hdr
 * @return
 */
int elf32_load_stage1(Elf32_Header *hdr) {
    /**
     * El ejemplo anterior asigna la memoria necesaria para la sección,
     * descrita por el campo sh_size del encabezado de la sección. Aunque
     * la función del ejemplo solo busca las secciones que deben asignarse,
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
 * Ejemplo de reubicación
 * Cargar un archivo ELF reubicable implica procesar todas las entradas
 * de reubicación presentes en el archivo (¡Recuerde asignar primero todas las
 * secciones SHT_NOBITS!). Este proceso comienza con la búsqueda de todas las
 * tablas de reubicación en el archivo, como se muestra en el código de ejemplo a
 * continuación.
 *
 * @param hdr
 * @return
 */
int elf32_load_stage2(Elf32_Header *hdr) {
    /**
     * Tenga en cuenta que el código solo procesa entradas Elf32_Rel, pero puede
     * modificarse para procesar también entradas con sumandos explícitos.
     * El código también se basa en una función llamada elf_do_reloc,
     * que se mostrará en el siguiente ejemplo.
     *
     * Esta función de ejemplo se detiene, muestra un mensaje de error y
     * devuelve un código de error si no puede procesar una reubicación.
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
 * Dado que la siguiente función es bastante compleja, se ha dividido en fragmentos
 * más pequeños y fáciles de manejar, y se ha explicado en detalle.
 *
 * Tenga en cuenta que el código a continuación asume que el archivo que se
 * reubica es un archivo ELF reubicable (los ejecutables ELF y los objetos compartidos
 * también pueden contener entradas de reubicación, pero se procesan de forma
 * ligeramente diferente).
 *
 * Tenga en cuenta también que sh_info, para los encabezados de
 * sección de tipo SHT_REL y SHT_RELA, almacena el encabezado de sección
 * al que se aplica la reubicación. (1)
 *
 * #define DO_386_32(S, A)	    ((S) + (A))
 * #define DO_386_PC32(S, A, P)	((S) + (A) - (P))
 *
 * El código anterior define las macrofunciones que se utilizan para
 * realizar los cálculos de reubicación. También recupera el
 * encabezado de la sección donde se encuentra el símbolo y
 * calcula una referencia a este. La variable addr indica el inicio
 * de la sección del símbolo, y ref se crea sumando el desplazamiento
 * del símbolo desde la entrada de reubicación. (2)
 *
 * A continuación, se accede al valor del símbolo que se está reubicando.
 * Si el índice de la tabla de símbolos almacenado en r_info no está
 * definido, el valor predeterminado es 0. El código también hace
 * referencia a una función llamada elf_get_symval(), implementada
 * previamente. Si el valor devuelto por la función es igual a
 * ELF_RELOC_ERR, se detiene la reubicación y se devuelve dicho
 * código de error. (3)
 *
 * Finalmente, este segmento de código detalla el proceso de reubicación,
 * realizando el cálculo necesario del símbolo reubicado y devolviendo su
 * valor en caso de éxito. Si el tipo de reubicación no es compatible,
 * se muestra un mensaje de error, se detiene la reubicación y la función
 * devuelve un código de error. Si no se han producido errores,
 * la reubicación está completa.
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
 * El encabezado del programa es una estructura que define información
 * sobre el comportamiento del programa ELF una vez cargado, así como
 * información de enlace en tiempo de ejecución. Los encabezados de programa
 * ELF (al igual que los encabezados de sección) se agrupan para formar la
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
 * y p_vaddr, que define la dirección donde debe existir el código
 * dependiente de la posición.
 *
 * @param mem es la ubicación del encabezado ELF
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

#endif