#ifndef LIB_PE_PARSE_H
#define LIB_PE_PARSE_H

#define _CRT_SECURE_NO_WARNINGS 1

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


typedef uint8_t                 _BYTE;
typedef uint16_t                _WORD;
typedef uint32_t               _DWORD;
typedef uint64_t               _QWORD;
typedef unsigned long           _LONG;
typedef long long           _LONGLONG;
typedef unsigned long long _ULONGLONG;



#pragma pack(push, 1)

#define ___IMAGE_DOS_SIGNATURE 0x5A4D
#define ___IMAGE_OS2_SIGNATURE 0x454E
#define ___IMAGE_OS2_SIGNATURE_LE 0x454C
#define ___IMAGE_VXD_SIGNATURE 0x454C
#define ___IMAGE_NT_SIGNATURE 0x00004550

/* AMD64 Specific types */
#define ___IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define ___IMAGE_REL_AMD64_ADDR64      0x0001
#define ___IMAGE_REL_AMD64_ADDR32      0x0002
#define ___IMAGE_REL_AMD64_ADDR32NB    0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define ___IMAGE_REL_AMD64_REL32       0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define ___IMAGE_REL_AMD64_REL32_1     0x0005
#define ___IMAGE_REL_AMD64_REL32_2     0x0006
#define ___IMAGE_REL_AMD64_REL32_3     0x0007
#define ___IMAGE_REL_AMD64_REL32_4     0x0008
#define ___IMAGE_REL_AMD64_REL32_5     0x0009
#define ___IMAGE_REL_AMD64_SECTION     0x000A
#define ___IMAGE_REL_AMD64_SECREL      0x000B
#define ___IMAGE_REL_AMD64_SECREL7     0x000C
#define ___IMAGE_REL_AMD64_TOKEN       0x000D
#define ___IMAGE_REL_AMD64_SREL32      0x000E
#define ___IMAGE_REL_AMD64_PAIR        0x000F
#define ___IMAGE_REL_AMD64_SSPAN32     0x0010

/*i386 Relocation types */

#define ___IMAGE_REL_I386_ABSOLUTE     0x0000
#define ___IMAGE_REL_I386_DIR16        0x0001
#define ___IMAGE_REL_I386_REL16        0x0002
#define ___IMAGE_REL_I386_DIR32        0x0006
#define ___IMAGE_REL_I386_DIR32NB      0x0007
#define ___IMAGE_REL_I386_SEG12        0x0009
#define ___IMAGE_REL_I386_SECTION      0x000A
#define ___IMAGE_REL_I386_SECREL       0x000B
#define ___IMAGE_REL_I386_TOKEN        0x000C
#define ___IMAGE_REL_I386_SECREL7      0x000D
#define ___IMAGE_REL_I386_REL32        0x0014

/* Section Characteristic Flags */

#define ___IMAGE_SCN_MEM_WRITE                 0x80000000
#define ___IMAGE_SCN_MEM_READ                  0x40000000
#define ___IMAGE_SCN_MEM_EXECUTE               0x20000000
#define ___IMAGE_SCN_ALIGN_16BYTES             0x00500000
#define ___IMAGE_SCN_MEM_NOT_CACHED            0x04000000
#define ___IMAGE_SCN_MEM_NOT_PAGED             0x08000000
#define ___IMAGE_SCN_MEM_SHARED                0x10000000
#define ___IMAGE_SCN_CNT_CODE                  0x00000020
#define ___IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040
#define ___IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
#define ___IMAGE_SCN_MEM_DISCARDABLE           0x02000000

#define ___DEFAULT_ADDR_LOAD_DLL                  0x10000000
#define ___DEFAULT_ADDR_LOAD_EXE                  0x00400000
#define ___DEFAULT_ADDR_LOAD_EXE_Windows_CE       0x00010000

#define ___IMAGE_SIZEOF_ROM_OPTIONAL_HEADER 56
#define ___IMAGE_SIZEOF_STD_OPTIONAL_HEADER 28
#define ___IMAGE_SIZEOF_NT_OPTIONAL32_HEADER 224
#define ___IMAGE_SIZEOF_NT_OPTIONAL64_HEADER 240

#define ___IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10b
#define ___IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20b
#define ___IMAGE_ROM_OPTIONAL_HDR_MAGIC        0x107   

#define ___IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define ___IMAGE_DOS_SIGNATURE                 0x5A4D

#define ___IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define ___IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define ___IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define ___IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define ___IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define ___IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define ___IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define ___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define ___IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define ___IMAGE_DIRECTORY_ENTRY_TLS             9
#define ___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define ___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define ___IMAGE_DIRECTORY_ENTRY_IAT            12
#define ___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define ___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define ___IMAGE_SIZEOF_SHORT_NAME              8
#define ___IMAGE_SIZEOF_SECTION_HEADER          40

#define ___IMAGE_SIZEOF_FILE_HEADER 20

#define ___IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define ___IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define ___IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define ___IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define ___IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define ___IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define ___IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define ___IMAGE_FILE_32BIT_MACHINE 0x0100
#define ___IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define ___IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define ___IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define ___IMAGE_FILE_SYSTEM 0x1000
#define ___IMAGE_FILE_DLL 0x2000
#define ___IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define ___IMAGE_FILE_BYTES_REVERSED_HI 0x8000

#define ___IMAGE_FILE_MACHINE_UNKNOWN 0
#define ___IMAGE_FILE_MACHINE_I386 0x014c
#define ___IMAGE_FILE_MACHINE_R3000 0x0162
#define ___IMAGE_FILE_MACHINE_R4000 0x0166
#define ___IMAGE_FILE_MACHINE_R10000 0x0168
#define ___IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
#define ___IMAGE_FILE_MACHINE_ALPHA 0x0184
#define ___IMAGE_FILE_MACHINE_SH3 0x01a2
#define ___IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define ___IMAGE_FILE_MACHINE_SH3E 0x01a4
#define ___IMAGE_FILE_MACHINE_SH4 0x01a6
#define ___IMAGE_FILE_MACHINE_SH5 0x01a8
#define ___IMAGE_FILE_MACHINE_ARM 0x01c0
#define ___IMAGE_FILE_MACHINE_ARMV7 0x01c4
#define ___IMAGE_FILE_MACHINE_ARMNT 0x01c4
#define ___IMAGE_FILE_MACHINE_ARM64 0xaa64
#define ___IMAGE_FILE_MACHINE_THUMB 0x01c2
#define ___IMAGE_FILE_MACHINE_AM33 0x01d3
#define ___IMAGE_FILE_MACHINE_POWERPC 0x01F0
#define ___IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define ___IMAGE_FILE_MACHINE_IA64 0x0200
#define ___IMAGE_FILE_MACHINE_MIPS16 0x0266
#define ___IMAGE_FILE_MACHINE_ALPHA64 0x0284
#define ___IMAGE_FILE_MACHINE_MIPSFPU 0x0366
#define ___IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
#define ___IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
#define ___IMAGE_FILE_MACHINE_TRICORE 0x0520
#define ___IMAGE_FILE_MACHINE_CEF 0x0CEF
#define ___IMAGE_FILE_MACHINE_EBC 0x0EBC
#define ___IMAGE_FILE_MACHINE_AMD64 0x8664
#define ___IMAGE_FILE_MACHINE_M32R 0x9041
#define ___IMAGE_FILE_MACHINE_CEE 0xc0ee

#define ___IMAGE_SUBSYSTEM_UNKNOWN 0
#define ___IMAGE_SUBSYSTEM_NATIVE 1
#define ___IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define ___IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define ___IMAGE_SUBSYSTEM_OS2_CUI 5
#define ___IMAGE_SUBSYSTEM_POSIX_CUI 7
#define ___IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define ___IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define ___IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define ___IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define ___IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#define ___IMAGE_SUBSYSTEM_EFI_ROM 13
#define ___IMAGE_SUBSYSTEM_XBOX 14
#define ___IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

#define ___IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#define ___IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define ___IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#define ___IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#define ___IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#define ___IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#define ___IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#define ___IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000
#define ___IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#define ___IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#define ___IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000


#ifndef UNALIGNED
    #if defined(_MSC_VER)
        #if defined(__ia64__) || defined(__x86_64__)
            #define UNALIGNED __unaligned
        #else
            #define UNALIGNED
        #endif
    #else
        // creo que es este es su equivalente para compiladores no mingw32:
        #define UNALIGNED __attribute__((packed))
    #endif
#endif /* UNALIGNED */

#ifdef __WIDL__
#  define __MINGW_EXTENSION
#else
#  if defined(__GNUC__) || defined(__GNUG__)
#    define __MINGW_EXTENSION __extension__
#  else
#    define __MINGW_EXTENSION
#  endif
#endif /* __WIDL__ */

/* Special case nameless struct/union.  */
#ifndef __C89_NAMELESS
#  define __C89_NAMELESS __MINGW_EXTENSION
#  define __C89_NAMELESSSTRUCTNAME
#  define __C89_NAMELESSSTRUCTNAME1
#  define __C89_NAMELESSSTRUCTNAME2
#  define __C89_NAMELESSSTRUCTNAME3
#  define __C89_NAMELESSSTRUCTNAME4
#  define __C89_NAMELESSSTRUCTNAME5
#  define __C89_NAMELESSUNIONNAME
#  define __C89_NAMELESSUNIONNAME1
#  define __C89_NAMELESSUNIONNAME2
#  define __C89_NAMELESSUNIONNAME3
#  define __C89_NAMELESSUNIONNAME4
#  define __C89_NAMELESSUNIONNAME5
#  define __C89_NAMELESSUNIONNAME6
#  define __C89_NAMELESSUNIONNAME7
#  define __C89_NAMELESSUNIONNAME8
#endif

#pragma pack(push)
typedef struct __IMAGE_DOS_HEADER {      // DOS .EXE header
    _WORD   e_magic;                     // Magic number
    _WORD   e_cblp;                      // Bytes on last page of file
    _WORD   e_cp;                        // Pages in file
    _WORD   e_crlc;                      // Relocations
    _WORD   e_cparhdr;                   // Size of header in paragraphs
    _WORD   e_minalloc;                  // Minimum extra paragraphs needed
    _WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    _WORD   e_ss;                        // Initial (relative) SS value
    _WORD   e_sp;                        // Initial SP value
    _WORD   e_csum;                      // Checksum
    _WORD   e_ip;                        // Initial IP value
    _WORD   e_cs;                        // Initial (relative) CS value
    _WORD   e_lfarlc;                    // File address of relocation table
    _WORD   e_ovno;                      // Overlay number
    _WORD   e_res[4];                    // Reserved words
    _WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    _WORD   e_oeminfo;                   // OEM information; e_oemid specific
    _WORD   e_res2[10];                  // Reserved words
    _LONG   e_lfanew;                    // File address of new exe header
  } ___IMAGE_DOS_HEADER, *___PIMAGE_DOS_HEADER;

typedef struct __IMAGE_DATA_DIRECTORY {
    _DWORD   VirtualAddress;
    _DWORD   Size;
} ___IMAGE_DATA_DIRECTORY, * ___PIMAGE_DATA_DIRECTORY;


typedef struct __IMAGE_OPTIONAL_HEADER {
    _WORD    Magic;
    _BYTE    MajorLinkerVersion;
    _BYTE    MinorLinkerVersion;
    _DWORD   SizeOfCode;
    _DWORD   SizeOfInitializedData;
    _DWORD   SizeOfUninitializedData;
    _DWORD   AddressOfEntryPoint;
    _DWORD   BaseOfCode;
    _DWORD   BaseOfData;
    _DWORD   ImageBase;
    _DWORD   SectionAlignment;
    _DWORD   FileAlignment;
    _WORD    MajorOperatingSystemVersion;
    _WORD    MinorOperatingSystemVersion;
    _WORD    MajorImageVersion;
    _WORD    MinorImageVersion;
    _WORD    MajorSubsystemVersion;
    _WORD    MinorSubsystemVersion;
    _DWORD   Win32VersionValue;
    _DWORD   SizeOfImage;
    _DWORD   SizeOfHeaders;
    _DWORD   CheckSum;
    _WORD    Subsystem;
    _WORD    DllCharacteristics;
    _DWORD   SizeOfStackReserve;
    _DWORD   SizeOfStackCommit;
    _DWORD   SizeOfHeapReserve;
    _DWORD   SizeOfHeapCommit;
    _DWORD   LoaderFlags;
    _DWORD   NumberOfRvaAndSizes;
    ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ___IMAGE_OPTIONAL_HEADER32, * ___PIMAGE_OPTIONAL_HEADER32;

typedef struct __IMAGE_OPTIONAL_HEADER64 {
    _WORD        Magic;
    _BYTE        MajorLinkerVersion;
    _BYTE        MinorLinkerVersion;
    _DWORD       SizeOfCode;
    _DWORD       SizeOfInitializedData;
    _DWORD       SizeOfUninitializedData;
    _DWORD       AddressOfEntryPoint;
    _DWORD       BaseOfCode;
    _ULONGLONG   ImageBase;
    _DWORD       SectionAlignment;
    _DWORD       FileAlignment;
    _WORD        MajorOperatingSystemVersion;
    _WORD        MinorOperatingSystemVersion;
    _WORD        MajorImageVersion;
    _WORD        MinorImageVersion;
    _WORD        MajorSubsystemVersion;
    _WORD        MinorSubsystemVersion;
    _DWORD       Win32VersionValue;
    _DWORD       SizeOfImage;
    _DWORD       SizeOfHeaders;
    _DWORD       CheckSum;
    _WORD        Subsystem;
    _WORD        DllCharacteristics;
    _ULONGLONG   SizeOfStackReserve;
    _ULONGLONG   SizeOfStackCommit;
    _ULONGLONG   SizeOfHeapReserve;
    _ULONGLONG   SizeOfHeapCommit;
    _DWORD       LoaderFlags;
    _DWORD       NumberOfRvaAndSizes;
    ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ___IMAGE_OPTIONAL_HEADER64, * ___PIMAGE_OPTIONAL_HEADER64;

typedef struct __IMAGE_FILE_HEADER {
    _WORD    Machine;
    _WORD    NumberOfSections;
    _DWORD   TimeDateStamp;
    _DWORD   PointerToSymbolTable;
    _DWORD   NumberOfSymbols;
    _WORD    SizeOfOptionalHeader;
    _WORD    Characteristics;
} ___IMAGE_FILE_HEADER, * ___PIMAGE_FILE_HEADER;

typedef struct __IMAGE_NT_HEADERS64 {
    _DWORD                                Signature;
    ___IMAGE_FILE_HEADER                FileHeader;
    ___IMAGE_OPTIONAL_HEADER64      OptionalHeader;
} ___IMAGE_NT_HEADERS64, *  ___PIMAGE_NT_HEADERS64;

typedef struct __IMAGE_NT_HEADERS {
    _DWORD                               Signature;
    ___IMAGE_FILE_HEADER               FileHeader;
    ___IMAGE_OPTIONAL_HEADER32     OptionalHeader;
} ___IMAGE_NT_HEADERS32, * ___PIMAGE_NT_HEADERS32;

typedef struct __IMAGE_IMPORT_DESCRIPTOR {
    __C89_NAMELESS union {
        _DWORD   Characteristics;
        _DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME__;
    _DWORD   TimeDateStamp;
    _DWORD   ForwarderChain;
    _DWORD   Name;
    _DWORD   FirstThunk;
} ___IMAGE_IMPORT_DESCRIPTOR UNALIGNED, * ___PIMAGE_IMPORT_DESCRIPTOR;

typedef struct __IMAGE_IMPORT_BY_NAME {
    _WORD    Hint;
    char   Name[100];
} ___IMAGE_IMPORT_BY_NAME, * ___PIMAGE_IMPORT_BY_NAME;

typedef struct __IMAGE_BASE_RELOCATION {
    _DWORD   VirtualAddress;
    _DWORD   SizeOfBlock;
} ___IMAGE_BASE_RELOCATION, * ___PIMAGE_BASE_RELOCATION;

typedef struct __IMAGE_SECTION_HEADER {
    _BYTE    Name[___IMAGE_SIZEOF_SHORT_NAME];
    union {
        _DWORD   PhysicalAddress;
        _DWORD   VirtualSize;
    } Misc;
    _DWORD   VirtualAddress;
    _DWORD   SizeOfRawData;
    _DWORD   PointerToRawData;
    _DWORD   PointerToRelocations;
    _DWORD   PointerToLinenumbers;
    _WORD    NumberOfRelocations;
    _WORD    NumberOfLinenumbers;
    _DWORD   Characteristics;
} ___IMAGE_SECTION_HEADER, * ___PIMAGE_SECTION_HEADER;

typedef struct __RICH_HEADER_INFO {
    int size;
    char* ptrToBuffer;
    int entries;
} RICH_HEADER_INFO, * PRICH_HEADER_INFO;
typedef struct __RICH_HEADER_ENTRY {
    _WORD  prodID;
    _WORD  buildID;
    _DWORD useCount;
} RICH_HEADER_ENTRY, * PRICH_HEADER_ENTRY;
typedef struct __RICH_HEADER {
    PRICH_HEADER_ENTRY entries;
} RICH_HEADER, * PRICH_HEADER;

typedef struct __ILT_ENTRY_32 {
    union {
        _DWORD ORDINAL           : 16;
        _DWORD HINT_NAME_TABE    : 32;
        _DWORD ORDINAL_NAME_FLAG  : 1;
    } FIELD_1;
} ILT_ENTRY_32, * PILT_ENTRY_32;
typedef struct __ILT_ENTRY_64 {
    union {
        _DWORD ORDINAL           : 16;
        _DWORD HINT_NAME_TABE    : 32;
    } FIELD_2;
    _DWORD ORDINAL_NAME_FLAG     : 1;
} ILT_ENTRY_64, * PILT_ENTRY_64;

typedef struct __BASE_RELOC_ENTRY {
    _WORD OFFSET : 12;
    _WORD TYPE : 4;
} BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;

#pragma pack(pop)

// Definicion de la estructura PE64FILE
typedef struct {
    char* NAME;
    FILE* Ppefile;
    int _import_directory_count;
    int _import_directory_size;
    int _basreloc_directory_count;

    // Encabezados
    ___IMAGE_DOS_HEADER PEFILE_DOS_HEADER;
    ___IMAGE_NT_HEADERS64 PEFILE_NT_HEADERS;

    // DOS HEADER
    _DWORD PEFILE_DOS_HEADER_EMAGIC;
    _LONG PEFILE_DOS_HEADER_LFANEW;

    // RICH HEADER
    RICH_HEADER_INFO PEFILE_RICH_HEADER_INFO;
    RICH_HEADER PEFILE_RICH_HEADER;

    // NT_HEADERS.Signature
    _DWORD PEFILE_NT_HEADERS_SIGNATURE;

    // NT_HEADERS.FileHeader
    _WORD PEFILE_NT_HEADERS_FILE_HEADER_MACHINE;
    _WORD PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS;
    _WORD PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER;

    // NT_HEADERS.OptionalHeader
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESS_OF_ENTRYPOINT;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASE_OF_CODE;
    _ULONGLONG PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE;
    _DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS;

    // Directorios de datos
    ___IMAGE_DATA_DIRECTORY PEFILE_EXPORT_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_IMPORT_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_RESOURCE_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_EXCEPTION_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_SECURITY_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_BASERELOC_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_DEBUG_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_ARCHITECTURE_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_GLOBALPTR_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_TLS_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_LOAD_CONFIG_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_BOUND_IMPORT_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_IAT_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_DELAY_IMPORT_DIRECTORY;
    ___IMAGE_DATA_DIRECTORY PEFILE_COM_DESCRIPTOR_DIRECTORY;

    // Encabezados de seccion
    ___PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;

    // Tabla de importacion
    ___PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;
    
    // Tabla de reubicacion base
    ___PIMAGE_BASE_RELOCATION PEFILE_BASERELOC_TABLE;
} PE64FILE;



#define SECTION_TYPE_CODE 1
#define SECTION_TYPE_INITIALIZED_DATA 2
#define SECTION_TYPE_UNINITIALIZED_DATA 3

void PE64FILE_Initialize(PE64FILE* peFile);
PE64FILE* PE64FILE_Create(char* _NAME, FILE* Ppefile);
void PE64FILE_Destroy(PE64FILE* peFile);
void PE64FILE_PrintInfo64(PE64FILE* peFile);
void ParseFile64(PE64FILE* peFile);
int locate64(PE64FILE* peFile, _DWORD VA);
_DWORD resolve64(PE64FILE* peFile, _DWORD VA, int index);
void ParseDOSHeader64(PE64FILE* peFile);
void PrintDOSHeaderInfo64(PE64FILE* peFile);
void ParseRichHeader64(PE64FILE* peFile);
void PrintRichHeaderInfo64(PE64FILE* peFile);
void ParseNTHeaders64(PE64FILE* peFile);
void PrintNTHeadersInfo64(PE64FILE* peFile);
void ParseSectionHeaders64(PE64FILE * peFile);
void PrintSectionHeadersInfo64(PE64FILE * peFile);
void ParseImportDirectory64(PE64FILE * peFile);
void PrintImportTableInfo64(PE64FILE * peFile);
void ParseBaseReloc64(PE64FILE * peFile);
void PrintBaseRelocationsInfo64(PE64FILE * peFile);
_DWORD align(_DWORD size, _DWORD alignment);
void AddNewSection64(
    PE64FILE* peFile, 
    const char* newSectionName, 
    _DWORD sizeOfRawData, 
    const void* sectionData, 
    int sectionType
);
void WriteModifiedPEFile64(
    PE64FILE* peFile, 
    const char* newFileName, 
    char* sectionData, 
    _DWORD sizeOfRawData
);
#endif