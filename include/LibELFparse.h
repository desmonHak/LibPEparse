#ifndef LIB_ELF_PARSE_H
#define LIB_ELF_PARSE_H

// para parametros que no se usaran bajo ciertas circustancias
#ifndef UNUSED_ARG
#define UNUSED_ARG(x) (void)(x)
#endif

// https://stevens.netmeister.org/631/elf.html
// https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=sysdeps/x86_64/dl-machine.h
// RIP -> https://www.tortall.net/projects/yasm/manual/html/nasm-effaddr.html

#define ERROR_ELF printf
#define DEBUG printf

// error en la relocalizacion
#define ELF_RELOC_ERR -1

#define DO_386_32(S, A)	        ((S) + (A))
#define DO_386_PC32(S, A, P)    ((S) + (A) - (P))

#ifndef PROT_READ
    #define PROT_READ   0x1  // Permite lectura
#endif
#ifndef PROT_WRITE
    #define PROT_WRITE  0x2  // Permite escritura
#endif
#ifndef PROT_EXEC
    #define PROT_EXEC   0x4  // Permite ejecucion
#endif

// Segment flag bits.
typedef enum flags_bit_segment_ELF {
    PF_X        = 0x1,          // Execute
    PF_W        = 0x2,          // Write
    PF_R        = 0x4,          // Read
    PF_MASKOS   = 0x0ff00000,   // Bits for operating system-specific semantics.
    #define PF_MASKPROC 0xf0000000    // Bits for processor-specific semantics.
} flags_bit_segment_ELF;
 

// tipos de sermento.
typedef enum type_segment_elf {
    PT_NULL = 0,            // Unused segment.
    PT_LOAD = 1,            // Loadable segment.
    PT_DYNAMIC = 2,         // Dynamic linking information.
    PT_INTERP = 3,          // Interpreter pathname.
    PT_NOTE = 4,            // Auxiliary information.
    PT_SHLIB = 5,           // Reserved.
    PT_PHDR = 6,            // The program header table itself.
    PT_TLS = 7,             // The thread-local storage template.
    PT_LOOS = 0x60000000,   // Lowest operating system-specific pt entry type.
    PT_HIOS = 0x6fffffff,   // Highest operating system-specific pt entry type.
    PT_LOPROC = 0x70000000, // Lowest processor-specific program hdr entry type.
    PT_HIPROC = 0x7fffffff, // Highest processor-specific program hdr entry type.
    
    // x86-64 program header types.
    // These all contain stack unwind tables.
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_SUNW_EH_FRAME = 0x6474e550,
    PT_SUNW_UNWIND = 0x6464e550,
    
    PT_GNU_STACK = 0x6474e551,    // Indicates stack executability.
    PT_GNU_RELRO = 0x6474e552,    // Read-only after relocation.
    PT_GNU_PROPERTY = 0x6474e553, // .note.gnu.property notes sections.
    
    PT_OPENBSD_MUTABLE = 0x65a3dbe5,   // Like bss, but not immutable.
    PT_OPENBSD_RANDOMIZE = 0x65a3dbe6, // Fill with random data.
    PT_OPENBSD_WXNEEDED = 0x65a3dbe7,  // Program does W^X violations.
    PT_OPENBSD_NOBTCFI = 0x65a3dbe8,   // Do not enforce branch target CFI.
    PT_OPENBSD_SYSCALLS = 0x65a3dbe9,  // System call sites.
    PT_OPENBSD_BOOTDATA = 0x65a41be6,  // Section for boot arguments.
    
    // ARM program header types.
    PT_ARM_ARCHEXT = 0x70000000, // Platform architecture compatibility info
    // These all contain stack unwind tables.
    PT_ARM_EXIDX = 0x70000001,
    PT_ARM_UNWIND = 0x70000001,
    // MTE memory tag segment type
    PT_AARCH64_MEMTAG_MTE = 0x70000002,
    
    // MIPS program header types.
    PT_MIPS_REGINFO = 0x70000000,  // Register usage information.
    PT_MIPS_RTPROC = 0x70000001,   // Runtime procedure table.
    PT_MIPS_OPTIONS = 0x70000002,  // Options segment.
    PT_MIPS_ABIFLAGS = 0x70000003, // Abiflags segment.
    
    // RISCV program header types.
    PT_RISCV_ATTRIBUTES = 0x70000003,
} type_segment_elf;




// https://wiki.osdev.org/ELF_Tutorial
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
/**
 * El formato de archivo ELF está diseñado para funcionar en diversas arquitecturas,
 * muchas de las cuales admiten distintos anchos de datos. Para su compatibilidad
 * con varios tipos de máquinas, el formato ELF proporciona una serie de directrices
 * para tipos de ancho fijo que conforman el diseño de la seccion y los datos
 * representados en los archivos de objeto. Puede optar por nombrar sus tipos de
 * forma diferente o usar directamente los tipos definidos en stdint.h, pero deben
 * cumplir con los mostrados anteriormente.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t Elf32_Half;	// Mitad sin signo
typedef uint32_t Elf32_Off;	    // Unsigned offset  / Desplazamiento sin signo
typedef uint32_t Elf32_Addr;	// Unsigned address / Direccion sin signo
typedef uint32_t Elf32_Word;	// Unsigned int     / Entero sin signo
typedef int32_t  Elf32_Sword;	// Signed int       / Entero con signo

typedef uint32_t Elf64_Word;	// Unsigned int     / Entero sin signo
typedef uint64_t Elf64_Addr;	// Unsigned address / Direccion sin signo
typedef uint64_t Elf64_Off;	    // Unsigned offset  / Desplazamiento sin signo
typedef uint16_t Elf64_Half;	// Mitad sin signo

typedef int32_t		Elf64_Sword;
typedef int64_t		Elf64_Sxword;
typedef uint64_t	Elf64_Lword;
typedef uint64_t	Elf64_Xword;

/*
 * Types of dynamic symbol hash table bucket and chain elements.
 *
 * This is inconsistent among 64 bit architectures, so a machine dependent
 * typedef is required.
 */

typedef Elf64_Word	Elf64_Hashelt;

/* Non-standard class-dependent datatype used for abstraction. */
typedef Elf64_Xword	Elf64_Size;
typedef Elf64_Sxword Elf64_Ssize;

/**
 * El encabezado ELF es el primero de un archivo ELF y proporciona informacion importante sobre
 * el archivo (como el tipo de máquina, la arquitectura y el orden de bytes, etc.),
 * además de permitir identificarlo y comprobar su validez. El encabezado ELF también
 * proporciona informacion sobre otras secciones del archivo, ya que pueden aparecer
 * en cualquier orden, variar en tamaño o incluso estar ausentes. Los primeros 4 bytes
 * (el número mágico) son comunes a todos los archivos ELF y se utilizan para identificar
 * el archivo. Al trabajar con el archivo mediante el tipo Elf32_Header definido
 * anteriormente, estos 4 bytes son accesibles desde los indices 0-3 del campo e_ident.
 */
enum Elf_Ident {
    EI_MAG0		    = 0, // 0x7F
    EI_MAG1		    = 1, // 'E'
    EI_MAG2		    = 2, // 'L'
    EI_MAG3		    = 3, // 'F'
    EI_CLASS	    = 4, // Architecture (32/64)
    EI_DATA		    = 5, // Byte Order
    EI_VERSION	    = 6, // ELF Version
    EI_OSABI	    = 7, // OS Specific
    EI_ABIVERSION	= 8, // OS Specific
    EI_PAD		    = 9, // Padding
    EI_NIDENT       = 16 // Size of e_ident[]
};


// OS ABI identification.
enum {
    ELFOSABI_NONE = 0,           // UNIX System V ABI
    ELFOSABI_SYSV = ELFOSABI_NONE,
    ELFOSABI_HPUX = 1,           // HP-UX operating system
    ELFOSABI_NETBSD = 2,         // NetBSD
    ELFOSABI_GNU = 3,            // GNU/Linux
    ELFOSABI_LINUX = 3,          // Historical alias for ELFOSABI_GNU.
    ELFOSABI_HURD = 4,           // GNU/Hurd
    ELFOSABI_SOLARIS = 6,        // Solaris
    ELFOSABI_AIX = 7,            // AIX
    ELFOSABI_IRIX = 8,           // IRIX
    ELFOSABI_FREEBSD = 9,        // FreeBSD
    ELFOSABI_TRU64 = 10,         // TRU64 UNIX
    ELFOSABI_MODESTO = 11,       // Novell Modesto
    ELFOSABI_OPENBSD = 12,       // OpenBSD
    ELFOSABI_OPENVMS = 13,       // OpenVMS
    ELFOSABI_NSK = 14,           // Hewlett-Packard Non-Stop Kernel
    ELFOSABI_AROS = 15,          // AROS
    ELFOSABI_FENIXOS = 16,       // FenixOS
    ELFOSABI_CLOUDABI = 17,      // Nuxi CloudABI
    ELFOSABI_CUDA = 51,          // NVIDIA CUDA architecture.
    ELFOSABI_FIRST_ARCH = 64,    // First architecture-specific OS ABI
    ELFOSABI_AMDGPU_HSA = 64,    // AMD HSA runtime
    ELFOSABI_AMDGPU_PAL = 65,    // AMD PAL runtime
    ELFOSABI_AMDGPU_MESA3D = 66, // AMD GCN GPUs (GFX6+) for MESA runtime
    ELFOSABI_ARM = 97,           // ARM
    ELFOSABI_ARM_FDPIC = 65,     // ARM FDPIC
    ELFOSABI_C6000_ELFABI = 64,  // Bare-metal TMS320C6000
    ELFOSABI_C6000_LINUX = 65,   // Linux TMS320C6000
    ELFOSABI_STANDALONE = 255,   // Standalone (embedded) application
    ELFOSABI_LAST_ARCH = 255     // Last Architecture-specific OS ABI
};


#define ELFMAG0	0x7F // e_ident[EI_MAG0]
#define ELFMAG1	'E'  // e_ident[EI_MAG1]
#define ELFMAG2	'L'  // e_ident[EI_MAG2]
#define ELFMAG3	'F'  // e_ident[EI_MAG3]

#define ELFDATANONE  (0)  // Invalid data encoding
#define ELFDATA2LSB  (1)  // Little Endian
#define ELFDATA2MSB  (2)  // Big Endian

#define ELFCLASSNONE (0)
#define ELFCLASS32	 (1)  // 32-bit Architecture
#define ELFCLASS64	 (2)  // 64-bit Architecture

/**
 * El primer campo del encabezado consta de 16 bytes, muchos de los cuales proporcionan
 * informacion importante sobre el archivo ELF, como la arquitectura prevista,
 * el orden de bytes y la informacion de la ABI. Dado que este tutorial se centra
 * en la implementacion de un cargador compatible con x86, solo se han incluido
 * las definiciones de valores relevantes.
 */
enum Elf_Type {
    ET_NONE		= 0, // Unkown Type
    ET_REL		= 1, // Relocatable File
    ET_EXEC		= 2  // Executable File
};


#define EV_NONE     (0)
#define EV_CURRENT	(1)  // ELF Current Version


#define ELF_NIDENT	16

/**
 * El formato de archivo ELF solo tiene un encabezado con ubicacion fija:
 * el encabezado ELF, presente al principio de cada archivo. El formato es
 * extremadamente flexible, ya que la ubicacion, el tamaño y la funcion de cada
 * encabezado (excepto el ELF) se describen en otro encabezado del archivo.
 */
typedef struct Elf32_Header {
    uint8_t		e_ident[ELF_NIDENT];    // valores magicos del ELF
    Elf32_Half	e_type;
    Elf32_Half	e_machine;              // ARCH a la que va destinada el ELF
    Elf32_Word	e_version;
    Elf32_Addr	e_entry;                // Punto de entrada
    Elf32_Off	e_phoff;
    Elf32_Off	e_shoff;                // offset donde inicia las secciones.
    Elf32_Word	e_flags;
    Elf32_Half	e_ehsize;
    Elf32_Half	e_phentsize;

    Elf32_Half	e_phnum;
    Elf32_Half	e_shentsize;
    Elf32_Half	e_shnum;                // numero de secciones en el ELF.
    Elf32_Half	e_shstrndx;             /**
                                         * offset para obtener la seccion de tabla de cadenas.
                                         * En caso de ser 0, es que no existe.
                                         */
} Elf32_Header;

typedef struct Elf64_Header {
    uint8_t e_ident[ELF_NIDENT];
    Elf64_Half e_type;      /* Reubicable=1, Ejecutable=2 (+ algunos * más...) */
    Elf64_Half e_machine;   /* Arquitectura de destino: MIPS=8 */
    Elf64_Word e_version;   /* Versión de Elf (debe ser 1) */
    Elf64_Addr e_entry;     /* Punto de entrada del código */
    Elf64_Off e_phoff;      /* Tabla de encabezados de programa */
    Elf64_Off e_shoff;      /* Tabla de encabezados de sección */
    Elf64_Word e_flags;     /* Banderas */
    Elf64_Half e_ehsize;    /* Tamaño del encabezado ELF */
    Elf64_Half e_phentsize; /* Tamaño de un segmento de programa
    * header */
    Elf64_Half e_phnum;     /* Número de segmento de programa
                             * encabezados */
    Elf64_Half e_shentsize; /* Tamaño de un encabezado de sección */
    Elf64_Half e_shnum;     /* Número de encabezados de sección */
    Elf64_Half e_shstrndx;  /* Índice de encabezado de sección de la
                             * tabla de cadenas para el encabezado de sección
                             * * nombres */
} Elf64_Header, Elf64_Ehdr;

/**
 * El formato ELF define numerosos tipos de secciones y sus encabezados correspondientes.
 * No todos están presentes en todos los archivos y no se garantiza su orden de aparicion.
 * Por lo tanto, para analizar y procesar estas secciones, el formato también define
 * encabezados de seccion, que contienen informacion como nombres, tamaños,
 * ubicaciones y otros datos relevantes. La lista de todos los encabezados
 * de seccion en una imagen ELF se denomina tabla de encabezados de seccion.
 */
typedef struct Elf32_Shdr {
    Elf32_Word	sh_name;
    Elf32_Word	sh_type;
    Elf32_Word	sh_flags;
    Elf32_Addr	sh_addr;
    Elf32_Off	sh_offset;
    Elf32_Word	sh_size;
    Elf32_Word	sh_link;
    Elf32_Word	sh_info;
    Elf32_Word	sh_addralign;
    Elf32_Word	sh_entsize;
} Elf32_Shdr;
/*
 * Section header.
 */

typedef struct {
	Elf64_Word	sh_name;	/* Section name (index into the
					   section header string table). */
	Elf64_Word	sh_type;	/* Section type. */
	Elf64_Xword	sh_flags;	/* Section flags. */
	Elf64_Addr	sh_addr;	/* Address in memory image. */
	Elf64_Off	sh_offset;	/* Offset in file. */
	Elf64_Xword	sh_size;	/* Size in bytes. */
	Elf64_Word	sh_link;	/* Index of a related section. */
	Elf64_Word	sh_info;	/* Depends on section type. */
	Elf64_Xword	sh_addralign;	/* Alignment in bytes. */
	Elf64_Xword	sh_entsize;	/* Size of each entry in section. */
} Elf64_Shdr;




/**
 * La tabla de encabezados de seccion contiene varios campos importantes, algunos de
 * los cuales tienen significados diferentes para cada seccion. Otro punto
 * interesante es que el campo sh_name no apunta directamente a una cadena,
 * sino que proporciona el desplazamiento de una cadena en la tabla de cadenas
 * de nombres de seccion (el indice de la tabla se define en el encabezado
 * ELF mediante el campo e_shstrndx). Cada encabezado también define la posicion
 * de la seccion en la imagen del archivo en el campo sh_offset, como
 * desplazamiento desde el inicio del archivo.
 */
# define SHN_UNDEF	(0x00) // Undefined/Not Present
# define SHN_ABS    0xFFF1 // Absolute symbol

enum ShT_Types {
    SHT_NULL	    = 0,   // Seccion nula
    SHT_PROGBITS    = 1,   // informacion del programa
    SHT_SYMTAB	    = 2,   // tabla de simbolos
    SHT_STRTAB	    = 3,   // tabla de strings/cadenas
    SHT_RELA	    = 4,   // Relocalizaciones (w/ addend)
    SHT_NOBITS	    = 8,   // Not present in file / no presente en el archivo
    SHT_REL		    = 9,   // Relocalizaciones (no addend)
};

/**
 * Arriba se muestran varias constantes relevantes para el tutorial
 * (existen muchas más). La enumeracion ShT_Types define diferentes tipos de secciones,
 * que corresponden a los valores almacenados en el campo sh_type del encabezado
 * de seccion. De forma similar, ShT_Attributes corresponde al campo sh_flags,
 * pero son indicadores de bits en lugar de valores independientes.
 */
enum ShT_Attributes {
    SHF_WRITE	  = 0x01, // Seccion de escritura
    SHF_ALLOC	  = 0x02, // Existe en memoria/reservar memoria para la seccion.
    SHF_EXECINSTR = 0x04  // (ejecutable)
};
/**
 *
 * @param hdr puntero a un ELF.
 * @return Numero de secciones disponibles en el ELF.
 */
static inline size_t Elf32_get_number_sections(Elf32_Header *hdr) {
    return hdr->e_shnum;
}

static inline size_t Elf64_get_number_sections(Elf64_Header *hdr) {
    return hdr->e_shnum;
}


/**
 * Acceder al encabezado de seccion no es muy dificil:
 * su posicion en la imagen de archivo se define mediante e_shoff
 * en el encabezado ELF, y el número de encabezados de seccion se define a su vez
 * mediante e_shnum. Cabe destacar que la primera entrada del encabezado de
 * seccion es nula; es decir, los campos del encabezado son 0.
 * Los encabezados de seccion son continuos, por lo que, dado un puntero a la
 * primera entrada, se puede acceder a las entradas posteriores mediante
 * operaciones simples con punteros o matrices.
 *
 * @param hdr puntero a un ELF.
 * @return se retorna un pùntero al inicio de las secciones
 */
static inline Elf32_Shdr *elf32_sheader(Elf32_Header *hdr) {
    return (Elf32_Shdr *)((uintptr_t)hdr + hdr->e_shoff);
}
static inline Elf64_Shdr* elf64_sheader(Elf64_Header *hdr)
{
    /* Cast heaven! */
    return (Elf64_Shdr*) ((uintptr_t) hdr + hdr->e_shoff);
}
// posibles valores para e_shoff
#define SHT_NULL            0x0  // Marca que la seccion no está activa
#define SHT_PROGBITS        0x1  // Seccion que contiene informacion definida por el programa
#define SHT_SYMTAB          0x2  // Seccion de tabla de simbolos
#define SHT_STRTAB          0x3  // Seccion de tabla de cadenas
#define SHT_RELA            0x4  // Seccion de entradas de reubicacion con añadidos
#define SHT_HASH            0x5  // Seccion de la tabla hash de simbolos
#define SHT_DYNAMIC         0x6  // Seccion para la vinculacion dinámica
#define SHT_NOTE            0x7  // Seccion para informacion de marca del archivo
#define SHT_NOBITS          0x8  // Seccion que no ocupa espacio en el archivo
#define SHT_REL             0x9  // Seccion de entradas de reubicacion sin añadidos
#define SHT_DYNSYM          0xb  // Seccion con un conjunto minimo de simbolos para vinculacion dinámica
#define SHT_FINI_ARRAY      0xf  // Seccion con una lista de punteros a funciones de terminacion
#define SHT_INIT_ARRAY      0xe  // Seccion con una lista de punteros a funciones de inicializacion
#define SHT_PREINIT_ARRAY   0x10 // Seccion con una lista de punteros a funciones de preinicializacion



/**
 * Funciones para obtener las seccion: estas tienes campos como .sh_flags o .sh_type
 *
 * @param hdr  puntero a un ELF.
 * @param idx ID de la seccion a la que se quiere acceder.
 * @return se retonar la direccion donde se contiene la seccion indicada.
 */
static inline Elf32_Shdr *elf32_section(Elf32_Header *hdr, uint16_t idx) {
    // se obtiene el inicio de las seccion. Se multiplica el ID * sizeof(Elf32_Shdr)
    // y se suma a la direccion devuelta por elf_sheader.
    return &elf32_sheader(hdr)[idx];
}
static inline Elf64_Shdr *elf64_section(Elf64_Header *hdr, uint16_t  idx) {
    // se obtiene el inicio de las seccion. Se multiplica el ID * sizeof(Elf32_Shdr)
    // y se suma a la direccion devuelta por elf_sheader.
    return &elf64_sheader(hdr)[idx];
}




/**
 * Un procedimiento importante es acceder a los nombres de seccion (ya que,
 * como se menciono anteriormente, el encabezado solo proporciona un desplazamiento
 * en la tabla de cadenas de nombres de seccion), lo cual también es bastante sencillo.
 * La operacion completa se puede resumir en una serie de pasos simples:
 *
 * 1 Obtener el indice del encabezado de seccion para la tabla de cadenas desde el encabezado ELF
 *      (almacenado en e_shstrndx). Asegúrese de comparar el indice con SHN_UNDEF, ya que
 *      la tabla podria no estar presente.
 *
 * 2 Acceder al encabezado de seccion en el indice dado y encontrar el desplazamiento
 *      de la tabla (almacenado en sh_offset).
 *
 * 3 Calcular la posicion de la tabla de cadenas en memoria utilizando el desplazamiento.
 *
 * 4 Crear un puntero al desplazamiento del nombre en la tabla de cadenas.
 *
 *
 * Tenga en cuenta que antes de intentar acceder al nombre de una seccion, primero
 * debe verificar que la seccion tenga un nombre (el desplazamiento dado por sh_name
 * no es igual a SHN_UNDEF).
 *
 * @param hdr  puntero a un ELF.
 * @return se retona la tabla se cadenas.
 */
static inline char *elf32_str_table(Elf32_Header *hdr) {
    if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
    return (char *)hdr + elf32_section(hdr, hdr->e_shstrndx)->sh_offset;
}
static inline char *elf64_str_table(Elf64_Header *hdr) {
    if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
    return (char *)hdr + elf64_section(hdr, hdr->e_shstrndx)->sh_offset;
}



static inline char *elf32_lookup_string(Elf32_Header *hdr, int offset) {
    char *strtab = elf32_str_table(hdr);
    if(strtab == NULL) return NULL;
    return strtab + offset;
}
static inline char *elf64_lookup_string(Elf64_Header *hdr, int offset) {
    char *strtab = elf64_str_table(hdr);
    if(strtab == NULL) return NULL;
    return strtab + offset;
}


/**
 * La tabla de simbolos es una seccion (o varias secciones) que existe
 * dentro del archivo ELF y define la ubicacion, el tipo, la visibilidad y
 * otras caracteristicas de los diversos simbolos declarados en el codigo
 * fuente original, creados durante la compilacion o el enlace, o presentes
 * de otro modo en el archivo. Dado que un objeto ELF puede tener varias
 * tablas de simbolos, es necesario iterar sobre los encabezados de seccion
 * del archivo o seguir una referencia desde otra seccion para acceder a una.
 */
typedef struct Elf32_Sym {
    Elf32_Word		st_name;
    Elf32_Addr		st_value;
    Elf32_Word		st_size;
    uint8_t			st_info;  /**
                               * tipo de simbolo y de vinculacion, se debe obtener
                               * con la macro ELF32_ST_BIND y ELF32_ST_TYPE
                               */
    uint8_t			st_other;
    Elf32_Half		st_shndx;
} Elf32_Sym;

typedef struct Elf64_Sym {
    Elf64_Word  st_name;   // indice en la tabla de strings del nombre del simbolo
    uint8_t     st_info;   // Tipo y vinculacion del simbolo
    uint8_t     st_other;  // Visibilidad del simbolo
    Elf64_Half  st_shndx;  // indice de la seccion a la que pertenece el simbolo
    Elf64_Addr  st_value;  // Valor del simbolo (direccion)
    Elf64_Xword st_size;   // Tamaño del objeto (si aplica)
} Elf64_Sym;


/*
 * Cada entrada de la tabla de simbolos contiene informacion importante, como el
 * nombre del simbolo (st_name, que puede ser STN_UNDEF), el valor del
 * simbolo (st_value, que puede ser la direccion absoluta o relativa del valor)
 * y el campo st_info, que contiene tanto el tipo de simbolo como su enlace.
 * Cabe destacar que la primera entrada de cada tabla de simbolos es nula,
 * por lo que todos sus campos son 0.
 *
 * Como se menciono anteriormente, st_info contiene tanto el tipo de simbolo como
 * la vinculacion, por lo que las dos macros anteriores proporcionan acceso a
 * los valores individuales. La enumeracion StT_Types proporciona varios tipos
 * de simbolo posibles, y StB_Bindings proporciona posibles vinculaciones de simbolos.
 *
 */

/**
 * Permite obtener la vinculacion del campo st_info
 * @param INFO campo st_info
 */
#define ELF32_ST_BIND(INFO)	((INFO) >> 4)
#define ELF64_ST_BIND ELF32_ST_BIND

/**
 * Permite obtener el tipo de simbolo del campo st_info
 * @param INFO campo st_info
 */
#define ELF32_ST_TYPE(INFO)	((INFO) & 0x0F)
#define ELF64_ST_TYPE ELF32_ST_TYPE

// Crea un valor st_info combinando binding y type
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0x0F))
#define ELF64_ST_INFO ELF32_ST_INFO

// Symbol bindings.
typedef enum StT_Bindings {
    STB_LOCAL = 0,  // Local symbol, not visible outside obj file containing def
    STB_GLOBAL = 1, // Global symbol, visible to all object files being combined
    STB_WEAK = 2,   // Weak symbol, like global but lower-precedence (ie. __attribute__((weak)))
    STB_GNU_UNIQUE = 10,
    STB_LOOS = 10,   // Lowest operating system-specific binding type
    STB_HIOS = 12,   // Highest operating system-specific binding type
    STB_LOPROC = 13, // Lowest processor-specific binding type
    STB_HIPROC = 15  // Highest processor-specific binding type
} StT_Bindings;

// Tipo de simbolo
enum {
  STT_NOTYPE = 0,     // Symbol's type is not specified
  STT_OBJECT = 1,     // Symbol is a data object (variable, array, etc.)
  STT_FUNC = 2,       // Symbol is executable code (function, etc.)
  STT_SECTION = 3,    // Symbol refers to a section
  STT_FILE = 4,       // Local, absolute symbol that refers to a file
  STT_COMMON = 5,     // An uninitialized common block
  STT_TLS = 6,        // Thread local data object
  STT_GNU_IFUNC = 10, // GNU indirect function
  STT_LOOS = 10,      // Lowest operating system-specific symbol type
  STT_HIOS = 12,      // Highest operating system-specific symbol type
  STT_LOPROC = 13,    // Lowest processor-specific symbol type
  STT_HIPROC = 15,    // Highest processor-specific symbol type
 
  // AMDGPU symbol types
  STT_AMDGPU_HSA_KERNEL = 10
};

/**
 * La tabla de cadenas
 * Conceptualmente, la tabla de cadenas es bastante simple:
 * consiste simplemente en un número de cadenas consecutivas terminadas en cero.
 * Los literales de cadena utilizados en el programa se almacenan en una de las tablas.
 * Existen diversas tablas de cadenas que pueden estar presentes en un objeto ELF, como
 * .strtab (la tabla de cadenas predeterminada),
 * .shstrtab (la tabla de cadenas de seccion) y
 * .dynstr (tabla de cadenas para enlaces dinámicos).
 *
 * Cada vez que el proceso de carga necesita acceder a una cadena,
 * utiliza un desplazamiento en una de las tablas de cadenas.
 * Este desplazamiento puede apuntar al principio de una cadena terminada
 * en cero, a un punto intermedio o incluso al propio terminador en cero,
 * según el uso y el escenario. El tamaño de la tabla de cadenas se especifica
 * mediante sh_size en la entrada de encabezado de seccion correspondiente.
 *
 * El cargador de programas más simple puede copiar todas las tablas de cadenas en
 * la memoria, pero una solucion más completa omitiria cualquiera que no sea necesaria
 * durante el tiempo de ejecucion, especialmente aquellas que no están marcadas
 * con SHF_ALLOC en su encabezado de seccion respectivo (como
 * .shstrtab, ya que los nombres de seccion no se usan en el tiempo de ejecucion del programa).
 */

/**
 * Secciones de Reubicacion
 * Los archivos ELF reubicables tienen múltiples usos en la programacion del kernel,
 * especialmente como modulos y controladores que se pueden cargar al inicio.
 * Son especialmente útiles porque son independientes de la posicion, por lo que pueden
 * colocarse fácilmente después del kernel o a partir de una direccion conveniente,
 * y no requieren su propio espacio de direcciones para funcionar.
 *
 * El proceso de reubicacion en si es conceptualmente simple, pero puede complicarse con
 * la introduccion de tipos de reubicacion complejos.
 *
 * La reubicacion comienza con una tabla de entradas de reubicacion,
 * que se pueden localizar mediante el encabezado de seccion correspondiente.
 *
 * Existen dos tipos diferentes de estructuras de reubicacion:
 * una con un añadido explicito (tipo de seccion SHT_RELA) y otra sin él
 * (tipo de seccion SHT_REL).
 *
 * Los enteros de reubicacion en la tabla son continuos y el número de entradas en
 * una tabla dada se puede calcular dividiendo el tamaño de la tabla
 * (dado por sh_size en el encabezado de seccion) por el tamaño de
 * cada entrada (dado por sh_entsize).
 *
 * Cada tabla de reubicacion es especifica de una sola seccion,
 * por lo que un solo archivo puede tener varias tablas de reubicacion
 * (pero todas las entradas dentro de una tabla determinada serán del
 * mismo tipo de estructura de reubicacion).
 */
typedef struct Elf32_Rel {
    Elf32_Addr		r_offset;
    Elf32_Word		r_info;
} Elf32_Rel;

typedef struct Elf32_Rela {
    Elf32_Addr		r_offset;
    Elf32_Word		r_info;
    Elf32_Sword		r_addend;
} Elf32_Rela;


typedef struct {
    Elf64_Addr  r_offset;   // Direccion donde aplicar la reubicacion
    Elf64_Xword r_info;     // Tipo y simbolo relacionados con la reubicacion
} Elf64_Rel;

typedef struct {
    Elf64_Addr  r_offset;   // Direccion donde aplicar la reubicacion
    Elf64_Xword r_info;     // Tipo y simbolo relacionados con la reubicacion
    Elf64_Sword r_addend;  // Valor constante adicional
} Elf64_Rela;

#include "RelocsELF/RelocsELF.h"


/*
 * Las definiciones anteriores corresponden a los diferentes tipos de estructura
 * para reubicaciones.
 * Cabe destacar el valor almacenado en r_info, ya que el byte superior
 * designa la entrada en la tabla de simbolos a la que se aplica la
 * reubicacion, mientras que el byte inferior almacena el tipo de reubicacion
 * que debe aplicarse. Tenga en cuenta que un archivo ELF puede tener
 * varias tablas de simbolos; por lo tanto, el indice de la tabla de
 * encabezado de seccion que hace referencia a la tabla de simbolos a
 * la que se aplican estas reubicaciones se encuentra en el campo sh_link
 * del encabezado de seccion de esta tabla de reubicacion.
 * El valor en r_offset indica la posicion relativa del simbolo que se está
 * reubicando dentro de su seccion.
 */

/**
 * entrada en la tabla de simbolos a la que se aplica la reubicacion
 * @param INFO campo r_info
 */
#define ELF32_R_SYM(INFO)	((INFO) >> 8)
#define ELF64_R_SYM(INFO)   ((INFO) >> 32)
/**
 * tipo de re-ubicacion que debe asignarse.
 * @param INFO campo r_info
 */
#define ELF32_R_TYPE(INFO)	((uint8_t)(INFO))
#define ELF64_R_TYPE(INFO)  ((INFO) & 0xFFFFFFFFL)


#define ELF64_R_INFO(sym, type) (((uint64_t)(sym) << 32) + ((type) & 0xFFFFFFFFL))
#define ELF32_R_INFO(sym, type) (((sym) << 8) + (uint8_t)(type))


/**
 * Como se menciono anteriormente, el campo r_info en Elf32_Rel(a)
 * hace referencia a dos valores distintos; por lo tanto, el conjunto de
 * macrofunciones anterior puede utilizarse para obtener los valores
 * individuales: ELF32_R_SYM() proporciona acceso al indice del simbolo
 * y ELF32_R_TYPE() proporciona acceso al tipo de reubicacion. La enumeracion
 * RtT_Types define los tipos de reubicacion que abarcará este tutorial.
 */
// ahora en RelocsELF/i386.h
/*enum RtT_Types {
    R_386_NONE		= 0, // No relocation
    R_386_32		= 1, // Symbol + Offset
    R_386_PC32		= 2  // Symbol + Offset - Section Offset
};*/

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
 */
typedef struct Elf32_Phdr {
    Elf32_Word		p_type;
    Elf32_Off		p_offset;
    Elf32_Addr		p_vaddr;
    Elf32_Addr		p_paddr;
    Elf32_Word		p_filesz;
    Elf32_Word		p_memsz;
    Elf32_Word		p_flags;
    Elf32_Word		p_align;
} Elf32_Phdr;

/*
 * Program header.
 */
typedef struct {
	Elf64_Word	p_type;		/* Entry type. */
	Elf64_Word	p_flags;	/* Access permission flags. */
	Elf64_Off	p_offset;	/* File offset of contents. */
	Elf64_Addr	p_vaddr;	/* Virtual address in memory image. */
	Elf64_Addr	p_paddr;	/* Physical address (not used). */
	Elf64_Xword	p_filesz;	/* Size of contents in file. */
	Elf64_Xword	p_memsz;	/* Size of contents in memory. */
	Elf64_Xword	p_align;	/* Alignment in memory and file. */
} Elf64_Phdr;

static inline Elf32_Phdr *elf32_getProgramHeaderTable(Elf32_Header *file)
{
	/* Cast hell! */
	return (Elf32_Phdr*) (((uintptr_t) file) + file->e_phoff);
}

static inline Elf64_Phdr *elf64_getProgramHeaderTable(Elf64_Header *file)
{
	/* Cast hell! */
	return (Elf64_Phdr*) (((uintptr_t) file) + file->e_phoff);
}

// valores para Elf64_Dyn/Elf32_Dyn . d_tag
#define DT_NULL         0   // Marca el final de la seccion dinámica
#define DT_NEEDED       1   // Nombre de una biblioteca necesaria
#define DT_PLTRELSZ     2   // Tamaño en bytes de las entradas de reubicacion del PLT
#define DT_PLTGOT       3   // Direccion de la tabla GOT utilizada por el PLT
#define DT_HASH         4   // Direccion de la tabla hash de simbolos
#define DT_STRTAB       5   // Direccion de la tabla de cadenas
#define DT_SYMTAB       6   // Direccion de la tabla de simbolos
#define DT_RELA         7   // Direccion de las entradas de reubicacion con añadido
#define DT_RELASZ       8   // Tamaño total de las entradas de reubicacion con añadido
#define DT_RELAENT      9   // Tamaño de una entrada de reubicacion con añadido
#define DT_STRSZ        10  // Tamaño de la tabla de cadenas
#define DT_SYMENT       11  // Tamaño de una entrada en la tabla de simbolos
#define DT_INIT         12  // Direccion de la funcion de inicializacion
#define DT_FINI         13  // Direccion de la funcion de finalizacion
#define DT_SONAME       14  // Nombre del objeto compartido
#define DT_RPATH        15  // Ruta de búsqueda de bibliotecas (obsoleto)
#define DT_SYMBOLIC     16  // Indica que las búsquedas de simbolos deben comenzar en este objeto
#define DT_REL          17  // Direccion de las entradas de reubicacion sin añadido
#define DT_RELSZ        18  // Tamaño total de las entradas de reubicacion sin añadido
#define DT_RELENT       19  // Tamaño de una entrada de reubicacion sin añadido
#define DT_PLTREL       20  // Tipo de reubicacion utilizada en el PLT
#define DT_DEBUG        21  // Reservado para depuracion
#define DT_TEXTREL      22  // Indica que existen reubicaciones en la seccion de texto
#define DT_JMPREL       23  // Direccion de las entradas de reubicacion del PLT
#define DT_BIND_NOW     24  // Indica que todas las reubicaciones deben resolverse al inicio
#define DT_INIT_ARRAY   25  // Direccion de la matriz de funciones de inicializacion
#define DT_FINI_ARRAY   26  // Direccion de la matriz de funciones de finalizacion
#define DT_INIT_ARRAYSZ 27  // Tamaño de la matriz de funciones de inicializacion
#define DT_FINI_ARRAYSZ 28  // Tamaño de la matriz de funciones de finalizacion
#define DT_RUNPATH      29  // Ruta de búsqueda de bibliotecas
#define DT_FLAGS        30  // Banderas
#define DT_ENCODING     32  // Valores codificados
#define DT_PREINIT_ARRAY    32  // Direccion de la matriz de funciones de preinicializacion
#define DT_PREINIT_ARRAYSZ  33  // Tamaño de la matriz de funciones de preinicializacion
#define DT_NUM          34  // Número de entradas definidas



/*
 * Dynamic structure.  The ".dynamic" section contains an array of them.
 */
typedef struct {
	Elf64_Sxword	d_tag;	/* Entry type. */
	union {
		Elf64_Xword	d_val;	/* Integer value. */
		Elf64_Addr	d_ptr;	/* Address value. */
	} d_un;
} Elf64_Dyn;
/**
 * Seccion dinamica (.dynamic)
 */
typedef struct {
    Elf32_Sword d_tag;     // Tipo de entrada (por ejemplo, DT_NEEDED, DT_STRTAB, etc.)
    union {
        Elf32_Word d_val;  // Valor entero (si aplica)
        Elf32_Addr d_ptr;  // Direccion o puntero (si aplica)
    } d_un;
} Elf32_Dyn;



bool elf_check_file(Elf32_Header *hdr);
const char *rel_type_x86(uint32_t type);
const char *rel_type_x64(uint32_t type);
void print_relocations(void *mem, int is64);
void print_needed_libs(void *mem, int is64);
void print_strings(void *mem, int is64);
void print_symbols(void *mem, int is64);
void *elf_lookup_symbol(const char *name);

int elf32_get_symval(Elf32_Header *hdr, int table, size_t idx);
void *elf32_load_file(void *file);
void *elf32_load_segment_to_memory(/*void *mem,*/ Elf64_Phdr *phdr, int elf_fd);
bool elf32_check_supported(Elf32_Header *hdr);
int elf32_do_reloc(Elf32_Header *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab);
int elf32_load_stage2(Elf32_Header *hdr);
int elf32_load_stage1(Elf32_Header *hdr);


/**
 * El siguiente paso para cargar un objeto ELF es comprobar que el archivo en cuestion
 * esté diseñado para ejecutarse en la máquina que lo cargo. De nuevo, el encabezado
 * ELF proporciona la informacion necesaria sobre el destino del archivo. El codigo
 * anterior asume que se ha implementado una funcion llamada elf_check_file()
 * (o se ha utilizado la proporcionada anteriormente) y que la máquina
 * local es i386, little-endian y de 32 bits. Además, solo permite cargar
 * archivos ejecutables y reubicables, aunque esto se puede modificar
 * según sea necesario.
 *
 * @param hdr
 * @return
 */
static inline void *elf32_load_rel(Elf32_Header *hdr) {
    int result;
    result = elf32_load_stage1(hdr);
    if(result == ELF_RELOC_ERR) {
        ERROR_ELF("Unable to load ELF file.\n");
        return NULL;
    }
    result = elf32_load_stage2(hdr);
    if(result == ELF_RELOC_ERR) {
        ERROR_ELF("Unable to load ELF file.\n");
        return NULL;
    }
    // TODO : Parse the program header (if present)
    return ((void *)((uintptr_t)(hdr->e_entry)));
}






static inline const char *get_section_name(void *hdr, int shstrndx, int sh_name, int is64) {
    if (is64) {
        Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)hdr + ((Elf64_Header *)hdr)->e_shoff);
        Elf64_Shdr *strtab = &shdr[shstrndx];
        return (const char *)hdr + strtab->sh_offset + sh_name;
    } else {
        Elf32_Shdr *shdr = (Elf32_Shdr *)((uint8_t *)hdr + ((Elf32_Header *)hdr)->e_shoff);
        Elf32_Shdr *strtab = &shdr[shstrndx];
        return (const char *)hdr + strtab->sh_offset + sh_name;
    }
}
typedef enum {
    ELFCLASS_UNKNOWN,
    ELFCLASS_32,
    ELFCLASS_64
} ElfClass;

typedef struct {
    void *mem;
    size_t size;
    ElfClass elf_class;
    union {
        Elf32_Header *ehdr32;
        Elf64_Header *ehdr64;
    };
} ElfFile;
void show_elf_code_data_sections_auto(const ElfFile *elf);
void show_elf_dynamic(const ElfFile *elf);

// GNU note types.
typedef enum type_notes_ELF {
    NT_GNU_ABI_TAG = 1,
    NT_GNU_HWCAP = 2,
    NT_GNU_BUILD_ID = 3,
    NT_GNU_GOLD_VERSION = 4,
    NT_GNU_PROPERTY_TYPE_0 = 5,
    #define FDO_PACKAGING_METADATA 0xcafe1a7e,
} type_notes_ELF;
void show_elf_notes(const ElfFile *elf);

// --- Carga y validacion ---
bool elf_mem_parse(ElfFile *elf, void *mem, size_t size);

// --- Extraccion de datos ---
size_t elf_section_count(const ElfFile *elf);
const char *elf_section_name(const ElfFile *elf, size_t idx);
uint32_t elf_section_type(const ElfFile *elf, size_t idx);
uint64_t elf_section_addr(const ElfFile *elf, size_t idx);
uint64_t elf_section_offset(const ElfFile *elf, size_t idx);
uint64_t elf_section_size(const ElfFile *elf, size_t idx);

// Simbolos
size_t elf_symbol_count(const ElfFile *elf, size_t *symtab_idx);
const char *elf_symbol_name(const ElfFile *elf, size_t symtab_idx, size_t sym_idx);
uint64_t elf_symbol_value(const ElfFile *elf, size_t symtab_idx, size_t sym_idx);
uint8_t elf_symbol_info(const ElfFile *elf, size_t symtab_idx, size_t sym_idx);
void show_elf_info(const ElfFile *elf);
// Relocaciones
size_t elf_relocation_count(const ElfFile *elf, size_t rel_idx);
void elf_get_relocation(const ElfFile *elf, size_t rel_idx, size_t rel_ent,
                            uint64_t *offset, uint32_t *type, int *sym_idx);

// Librerias requeridas
size_t elf_needed_count(const ElfFile *elf);
const char *elf_needed_name(const ElfFile *elf, size_t idx);

// Strings de tablas de cadenas
void elf_iterate_strings(const ElfFile *elf, void (*cb)(const char *str, void *user), void *user);

// --- Mostrar informacion extendida de simbolos ---
static inline const char *sym_type_str(uint8_t info) {
    switch (info & 0xf) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        default: return "OTHER";
    }
}
static inline const char *sym_bind_str(uint8_t info) {
    switch (info >> 4) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        default: return "OTHER";
    }
}



#ifdef __cplusplus
}
#endif

#endif
