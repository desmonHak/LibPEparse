#ifndef LIB_PE_PARSE_H
#define LIB_PE_PARSE_H

#include <stdlib.h>
#include <errno.h>

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

typedef uint8_t                 _BYTE;
typedef uint16_t                _WORD;
typedef uint32_t               _DWORD;
typedef uint64_t               _QWORD;
typedef unsigned long           _LONG;
typedef long long           _LONGLONG;
typedef unsigned long long _ULONGLONG;



#pragma pack(push, 1)
/* AMD64 Specific types */
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define IMAGE_REL_AMD64_REL32       0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

/*i386 Relocation types */

#define IMAGE_REL_I386_ABSOLUTE     0x0000
#define IMAGE_REL_I386_DIR16        0x0001
#define IMAGE_REL_I386_REL16        0x0002
#define IMAGE_REL_I386_DIR32        0x0006
#define IMAGE_REL_I386_DIR32NB      0x0007
#define IMAGE_REL_I386_SEG12        0x0009
#define IMAGE_REL_I386_SECTION      0x000A
#define IMAGE_REL_I386_SECREL       0x000B
#define IMAGE_REL_I386_TOKEN        0x000C
#define IMAGE_REL_I386_SECREL7      0x000D
#define IMAGE_REL_I386_REL32        0x0014

/* Section Characteristic Flags */

#define IMAGE_SCN_MEM_WRITE                 0x80000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_ALIGN_16BYTES             0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED            0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED             0x08000000
#define IMAGE_SCN_MEM_SHARED                0x10000000
#define IMAGE_SCN_CNT_CODE                  0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE           0x02000000

#define DEFAULT_ADDR_LOAD_DLL                  0x10000000
#define DEFAULT_ADDR_LOAD_EXE                  0x00400000
#define DEFAULT_ADDR_LOAD_EXE_Windows_CE       0x00010000

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
    union {
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

    // Encabezados de sección
    ___PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;

    // Tabla de importación
    ___PIMAGE_IMPORT_DESCRIPTOR PEFILE_IMPORT_TABLE;
    
    // Tabla de reubicación base
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