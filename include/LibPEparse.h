#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// fuente original: https://github.com/0xRick/PE-Parser/blob/main/PE-Parser/PE64FILE.cpp

typedef uint8_t                 BYTE;
typedef uint16_t                WORD;
typedef uint32_t               DWORD;
typedef uint64_t               QWORD;
typedef unsigned long           LONG;
typedef long long           LONGLONG;
typedef unsigned long long ULONGLONG;

#define ___IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10b
#define ___IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20b
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

typedef struct __IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} ___IMAGE_DOS_HEADER, * ___PIMAGE_DOS_HEADER;

typedef struct __IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} ___IMAGE_DATA_DIRECTORY, * ___PIMAGE_DATA_DIRECTORY;


typedef struct __IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ___IMAGE_OPTIONAL_HEADER32, * ___PIMAGE_OPTIONAL_HEADER32;

typedef struct __IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    ___IMAGE_DATA_DIRECTORY DataDirectory[___IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ___IMAGE_OPTIONAL_HEADER64, * ___PIMAGE_OPTIONAL_HEADER64;

typedef struct __IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} ___IMAGE_FILE_HEADER, * ___PIMAGE_FILE_HEADER;

typedef struct __IMAGE_NT_HEADERS64 {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    ___IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} ___IMAGE_NT_HEADERS64, * ___PIMAGE_NT_HEADERS64;

typedef struct __IMAGE_NT_HEADERS {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    ___IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} ___IMAGE_NT_HEADERS32, * ___PIMAGE_NT_HEADERS32;

typedef struct __IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME__;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} ___IMAGE_IMPORT_DESCRIPTOR, * ___PIMAGE_IMPORT_DESCRIPTOR;

typedef struct __IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    char   Name[100];
} ___IMAGE_IMPORT_BY_NAME, * ___PIMAGE_IMPORT_BY_NAME;

typedef struct __IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} ___IMAGE_BASE_RELOCATION, * ___PIMAGE_BASE_RELOCATION;

typedef struct __IMAGE_SECTION_HEADER {
    BYTE    Name[___IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} ___IMAGE_SECTION_HEADER, * ___PIMAGE_SECTION_HEADER;

typedef struct __RICH_HEADER_INFO {
    int size;
    char* ptrToBuffer;
    int entries;
} RICH_HEADER_INFO, * PRICH_HEADER_INFO;
typedef struct __RICH_HEADER_ENTRY {
    WORD  prodID;
    WORD  buildID;
    DWORD useCount;
} RICH_HEADER_ENTRY, * PRICH_HEADER_ENTRY;
typedef struct __RICH_HEADER {
    PRICH_HEADER_ENTRY entries;
} RICH_HEADER, * PRICH_HEADER;

typedef struct __ILT_ENTRY_32 {
    union {
        DWORD ORDINAL : 16;
        DWORD HINT_NAME_TABE : 32;
        DWORD ORDINAL_NAME_FLAG : 1;
    } FIELD_1;
} ILT_ENTRY_32, * PILT_ENTRY_32;
typedef struct __ILT_ENTRY_64 {
    union {
        DWORD ORDINAL : 16;
        DWORD HINT_NAME_TABE : 32;
    } FIELD_2;
    DWORD ORDINAL_NAME_FLAG : 1;
} ILT_ENTRY_64, * PILT_ENTRY_64;

typedef struct __BASE_RELOC_ENTRY {
    WORD OFFSET : 12;
    WORD TYPE : 4;
} BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;

// Definición de la estructura PE64FILE
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
    DWORD PEFILE_DOS_HEADER_EMAGIC;
    LONG PEFILE_DOS_HEADER_LFANEW;

    // RICH HEADER
    RICH_HEADER_INFO PEFILE_RICH_HEADER_INFO;
    RICH_HEADER PEFILE_RICH_HEADER;

    // NT_HEADERS.Signature
    DWORD PEFILE_NT_HEADERS_SIGNATURE;

    // NT_HEADERS.FileHeader
    WORD PEFILE_NT_HEADERS_FILE_HEADER_MACHINE;
    WORD PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS;
    WORD PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER;

    // NT_HEADERS.OptionalHeader
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESS_OF_ENTRYPOINT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASE_OF_CODE;
    ULONGLONG PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE;
    DWORD PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS;

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

    // Encabezados de sección
    ___PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;

    // Tabla de importación
    ___PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;
    
    // Tabla de reubicación base
    ___PIMAGE_BASE_RELOCATION PEFILE_BASERELOC_TABLE;
} PE64FILE;