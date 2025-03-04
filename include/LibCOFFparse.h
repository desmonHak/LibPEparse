#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* --- Definiciones COFF (empaquetadas) --- */
#pragma pack(push, 1)

typedef struct _COFF_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

typedef struct _SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        struct {
            uint32_t Zero;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct _RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} RELOCATION;

#pragma pack(pop)

/* --- Otras definiciones --- */
typedef struct {
    char *data;
    size_t size;
} Data;

typedef struct {
    char name[9];  // 8 caracteres + terminador nulo
    uint32_t characteristics;
    Data data;
    RELOCATION *relocations;
    int numRelocations;
} NewSection;

    /* AMD64 Specific types */
    #define IMAGE_REL_AMD64_ABSOLUTE    0x0000
    #define IMAGE_REL_AMD64_ADDR64      0x0001
    #define IMAGE_REL_AMD64_ADDR32      0x0002
    #define IMAGE_REL_AMD64_ADDR32NB    0x0003
    #define IMAGE_REL_AMD64_REL32       0x0004
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

    /* i386 Relocation types */
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

    
    