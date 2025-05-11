#ifndef LIB_ELF_PARSE_H
#define LIB_ELF_PARSE_H

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

#define PF_X 0x1  // Ejecutable
#define PF_W 0x2  // Escribible
#define PF_R 0x4  // Legible



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

typedef int64_t  Elf64_Sword;	// Signed int       / Entero con signo
typedef uint64_t Elf64_Word;	// Unsigned int     / Entero sin signo
typedef uint64_t Elf64_Addr;	// Unsigned address / Direccion sin signo
typedef uint64_t Elf64_Off;	    // Unsigned offset  / Desplazamiento sin signo
typedef uint32_t Elf64_Half;	// Mitad sin signo

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

typedef enum {
    ELFOSABI_NONE      = 0,   // No extensions or unspecified
    ELFOSABI_HPUX      = 1,   // Hewlett-Packard HP-UX
    ELFOSABI_NETBSD    = 2,   // NetBSD
    ELFOSABI_LINUX     = 3,   // Linux
    ELFOSABI_SOLARIS   = 6,   // Sun Solaris
    ELFOSABI_AIX       = 7,   // AIX
    ELFOSABI_IRIX      = 8,   // IRIX
    ELFOSABI_FREEBSD   = 9,   // FreeBSD
    ELFOSABI_TRU64     = 10,  // Compaq TRU64 UNIX
    ELFOSABI_MODESTO   = 11,  // Novell Modesto
    ELFOSABI_OPENBSD   = 12,  // Open BSD
    ELFOSABI_OPENVMS   = 13,  // Open VMS
    ELFOSABI_NSK       = 14   // Hewlett-Packard Non-Stop Kernel
    // 64–255 reserved for architecture-specific values
} ElfOSABI;


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

#define EM_NONE 0                  // No machine
#define EM_M32 1                   // AT&T WE 32100
#define EM_SPARC 2                 // SPARC
#define EM_386 3                   // Intel 80386
#define EM_68K 4                   // Motorola 68000
#define EM_88K 5                   // Motorola 88000
#define EM_RESERVED_6 6            // Reserved for future use (was EM_486)
#define EM_860 7                   // Intel 80860
#define EM_MIPS 8                  // MIPS I Architecture
#define EM_S370 9                  // IBM System/370 Processor
#define EM_MIPS_RS3_LE 10          // MIPS RS3000 Little-endian
#define EM_RESERVED_11_14 11-14    // Reserved for future use
#define EM_PARISC 15               // Hewlett-Packard PA-RISC
#define EM_RESERVED_16 16          // Reserved for future use
#define EM_VPP500 17               // Fujitsu VPP500
#define EM_SPARC32PLUS 18          // Enhanced instruction set SPARC
#define EM_960 19                  // Intel 80960
#define EM_PPC 20                  // PowerPC
#define EM_PPC64 21                // 64-bit PowerPC
#define EM_S390 22                 // IBM System/390 Processor
#define EM_RESERVED_23_35 23-35    // Reserved for future use
#define EM_V800 36                 // NEC V800
#define EM_FR20 37                 // Fujitsu FR20
#define EM_RH32 38                 // TRW RH-32
#define EM_RCE 39                  // Motorola RCE
#define EM_ARM 40                  // Advanced RISC Machines ARM
#define EM_ALPHA 41                // Digital Alpha
#define EM_SH 42                   // Hitachi SH
#define EM_SPARCV9 43              // SPARC Version 9
#define EM_TRICORE 44              // Siemens TriCore embedded processor
#define EM_ARC 45                  // Argonaut RISC Core, Argonaut Technologies Inc.
#define EM_H8_300 46               // Hitachi H8/300
#define EM_H8_300H 47              // Hitachi H8/300H
#define EM_H8S 48                  // Hitachi H8S
#define EM_H8_500 49               // Hitachi H8/500
#define EM_IA_64 50                // Intel IA-64 processor architecture
#define EM_MIPS_X 51               // Stanford MIPS-X
#define EM_COLDFIRE 52             // Motorola ColdFire
#define EM_68HC12 53               // Motorola M68HC12
#define EM_MMA 54                  // Fujitsu MMA Multimedia Accelerator
#define EM_PCP 55                  // Siemens PCP
#define EM_NCPU 56                 // Sony nCPU embedded RISC processor
#define EM_NDR1 57                 // Denso NDR1 microprocessor
#define EM_STARCORE 58             // Motorola Star*Core processor
#define EM_ME16 59                 // Toyota ME16 processor
#define EM_ST100 60                // STMicroelectronics ST100 processor
#define EM_TINYJ 61                // Advanced Logic Corp. TinyJ embedded processor family
#define EM_X86_64 62               // AMD x86-64 architecture
#define EM_PDSP 63                 // Sony DSP Processor
#define EM_PDP10 64                // Digital Equipment Corp. PDP-10
#define EM_PDP11 65                // Digital Equipment Corp. PDP-11
#define EM_FX66 66                 // Siemens FX66 microcontroller
#define EM_ST9PLUS 67              // STMicroelectronics ST9+ 8/16 bit microcontroller
#define EM_ST7 68                  // STMicroelectronics ST7 8-bit microcontroller
#define EM_68HC16 69               // Motorola MC68HC16 Microcontroller
#define EM_68HC11 70               // Motorola MC68HC11 Microcontroller
#define EM_68HC08 71               // Motorola MC68HC08 Microcontroller
#define EM_68HC05 72               // Motorola MC68HC05 Microcontroller
#define EM_SVX 73                  // Silicon Graphics SVx
#define EM_ST19 74                 // STMicroelectronics ST19 8-bit microcontroller
#define EM_VAX 75                  // Digital VAX
#define EM_CRIS 76                 // Axis Communications 32-bit embedded processor
#define EM_JAVELIN 77              // Infineon Technologies 32-bit embedded processor
#define EM_FIREPATH 78             // Element 14 64-bit DSP Processor
#define EM_ZSP 79                  // LSI Logic 16-bit DSP Processor
#define EM_MMIX 80                 // Donald Knuth's educational 64-bit processor
#define EM_HUANY 81                // Harvard University machine-independent object files
#define EM_PRISM 82                // SiTera Prism
#define EM_AVR 83                  // Atmel AVR 8-bit microcontroller
#define EM_FR30 84                 // Fujitsu FR30
#define EM_D10V 85                 // Mitsubishi D10V
#define EM_D30V 86                 // Mitsubishi D30V
#define EM_V850 87                 // NEC v850
#define EM_M32R 88                 // Mitsubishi M32R
#define EM_MN10300 89              // Matsushita MN10300
#define EM_MN10200 90              // Matsushita MN10200
#define EM_PJ 91                   // picoJava
#define EM_OPENRISC 92             // OpenRISC 32-bit embedded processor
#define EM_ARC_A5 93               // ARC Cores Tangent-A5
#define EM_XTENSA 94               // Tensilica Xtensa Architecture
#define EM_VIDEOCORE 95            // Alphamosaic VideoCore processor
#define EM_TMM_GPP 96              // Thompson Multimedia General Purpose Processor
#define EM_NS32K 97                // National Semiconductor 32000 series
#define EM_TPC 98                  // Tenor Network TPC processor
#define EM_SNP1K 99                // Trebia SNP 1000 processor
#define EM_ST200 100               // STMicroelectronics (www.st.com) ST200 microcontroller

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
    uint8_t         e_ident[ELF_NIDENT];
    Elf32_Half      e_type;	/* Relocatable=1, Executable=2 (+ some
                 * more ..) */
    Elf32_Half      e_machine;	/* Target architecture: MIPS=8 */
    Elf32_Word      e_version;	/* Elf version (should be 1) */
    Elf64_Addr      e_entry;	/* Code entry point */
    Elf64_Off       e_phoff;	/* Program header table */
    Elf64_Off       e_shoff;	/* Section header table */
    Elf32_Word      e_flags;	/* Flags */
    Elf32_Half      e_ehsize;	/* ELF header size */
    Elf32_Half      e_phentsize;	/* Size of one program segment
                                    * header */
    Elf32_Half      e_phnum;	/* Number of program segment
                                * headers */
    Elf32_Half      e_shentsize;	/* Size of one section header */
    Elf32_Half      e_shnum;	/* Number of section headers */
    Elf32_Half      e_shstrndx;	/* Section header index of the
                     * string table for section header
                     * * names */
} Elf64_Header;

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
typedef struct Elf64_Shdr {
    Elf32_Word      sh_name;
    Elf32_Word      sh_type;
    Elf64_Word      sh_flags;
    Elf64_Addr      sh_addr;
    Elf64_Off       sh_offset;
    Elf64_Word      sh_size;
    Elf32_Word      sh_link;
    Elf32_Word      sh_info;
    Elf64_Word      sh_addralign;
    Elf64_Word      sh_entsize;
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
    SHF_WRITE	= 0x01, // Seccion de escritura
    SHF_ALLOC	= 0x02  // Existe en memoria/reservar memoria para la seccion.
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
    return (Elf32_Shdr *)((int)hdr + hdr->e_shoff);
}
static inline Elf64_Shdr* elf64_sheader(Elf64_Header *hdr)
{
    /* Cast heaven! */
    return (Elf64_Shdr*) ((uintptr_t) hdr + hdr->e_shoff);
}


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
    Elf64_Word  st_size;   // Tamaño del objeto (si aplica)
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

// Vinculacion
enum StT_Bindings {
    STB_LOCAL		= 0, // Local scope
    STB_GLOBAL		= 1, // Global scope
    STB_WEAK		= 2  // Weak, (ie. __attribute__((weak)))
};

// Tipo de simbolo
enum StT_Types {
    STT_NOTYPE,    // Tipo desconocido
    STT_OBJECT,    // Variable
    STT_FUNC,      // Funcion
    STT_SECTION,   // Marca una seccion
    STT_FILE,      // Nombre de archivo
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
    Elf64_Word r_info;     // Tipo y simbolo relacionados con la reubicacion
} Elf64_Rel;

typedef struct {
    Elf64_Addr  r_offset;   // Direccion donde aplicar la reubicacion
    Elf64_Word r_info;     // Tipo y simbolo relacionados con la reubicacion
    Elf64_Sword r_addend;  // Valor constante adicional
} Elf64_Rela;


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


#define ELF64_R_INFO(sym, ttype) (((uint64_t)(sym) << 32) + ((type) & 0xFFFFFFFFL))
#define ELF32_R_INFO(sym, type) (((sym) << 8) + (uint8_t)(type))


/**
 * Como se menciono anteriormente, el campo r_info en Elf32_Rel(a)
 * hace referencia a dos valores distintos; por lo tanto, el conjunto de
 * macrofunciones anterior puede utilizarse para obtener los valores
 * individuales: ELF32_R_SYM() proporciona acceso al indice del simbolo
 * y ELF32_R_TYPE() proporciona acceso al tipo de reubicacion. La enumeracion
 * RtT_Types define los tipos de reubicacion que abarcará este tutorial.
 */
enum RtT_Types {
    R_386_NONE		= 0, // No relocation
    R_386_32		= 1, // Symbol + Offset
    R_386_PC32		= 2  // Symbol + Offset - Section Offset
};

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
typedef struct Elf64_Phdr {
    Elf32_Word      p_type;	/* Segment type: Loadable segment = 1 */
    Elf32_Word      p_flags;	/* Flags: logical "or" of PF_
                     * constants below */
    Elf64_Off       p_offset;	/* Offset of segment in file */
    Elf64_Addr      p_vaddr;	/* Reqd virtual address of segment
                     * when loading */
    Elf64_Addr      p_paddr;	/* Reqd physical address of
                     * segment */
    Elf32_Word      p_filesz;	/* How many bytes this segment
                     * occupies in file */
    Elf64_Word      p_memsz;	/* How many bytes this segment
                     * should occupy in * memory (when
                     * * loading, expand the segment
                     * by * concatenating enough zero
                     * bytes to it) */
    Elf64_Word      p_align;	/* Reqd alignment of segment in
                     * memory */
} Elf64_Phdr;

static inline Elf32_Phdr *elf32_getProgramHeaderTable(Elf32_Header *file)
{
	/* Cast hell! */
	return (Elf32_Phdr*) (((int) file) + file->e_phoff);
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


/**
 * Seccion dinamica (.dynamic)
 */
typedef struct Elf64_Dyn {
    Elf64_Word d_tag;
    union {
        Elf64_Word d_val;
        Elf64_Word d_ptr;
    } d_un;
} Elf64_Dyn;

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
void *elf32_load_segment_to_memory(void *mem, Elf64_Phdr *phdr, int elf_fd);
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
    return (void *)hdr->e_entry;
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

// Relocaciones
size_t elf_relocation_count(const ElfFile *elf, size_t rel_idx);
void elf_get_relocation(const ElfFile *elf, size_t rel_idx, size_t rel_ent,
                            uint64_t *offset, uint32_t *type, int *sym_idx);

// Librerias requeridas
size_t elf_needed_count(const ElfFile *elf);
const char *elf_needed_name(const ElfFile *elf, size_t idx);

// Strings de tablas de cadenas
void elf_iterate_strings(const ElfFile *elf, void (*cb)(const char *str, void *user), void *user);

#ifdef __cplusplus
}
#endif

#endif
