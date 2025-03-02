#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

typedef struct {
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

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;


// Structure for data to be written into a section
typedef struct {
    char* data;
    uint32_t size;
} SectionData;

// Structure to hold relocation information (simplified)
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} RELOCATION;

// Structure for a section to be added
typedef struct {
    char name[8];
    uint32_t characteristics;
    SectionData data;
    RELOCATION* relocations;
    uint32_t numRelocations;
} NewSection;



#pragma pack(pop)