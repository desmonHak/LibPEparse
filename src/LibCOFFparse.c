#include "../include/LibCOFFparse.h"

// --- Utility Functions ---
uint32_t align(uint32_t value, uint32_t alignment) {
    return ((value + alignment - 1) / alignment) * alignment;
}

int create_coff_file(const char* filename, COFF_HEADER* header, SECTION_HEADER* sections, NewSection* newSections, int numSections, COFF_SYMBOL* symbols, uint32_t numSymbols, char* stringTable, uint32_t stringTableSize) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        return 1;
    }

    // Write COFF Header
    fwrite(header, 1, sizeof(COFF_HEADER), file);

    // Write Section Headers
    fwrite(sections, 1, sizeof(SECTION_HEADER) * numSections, file);

    // Write Section Data with proper alignment
    for (int i = 0; i < numSections; i++) {
        fseek(file, sections[i].PointerToRawData, SEEK_SET);
        fwrite(newSections[i].data.data, 1, newSections[i].data.size, file);
        
        // Pad the section to align with SizeOfRawData
        uint32_t padding = sections[i].SizeOfRawData - newSections[i].data.size;
        char* padBuffer = calloc(padding, 1);
        fwrite(padBuffer, 1, padding, file);
        free(padBuffer);
    }

    // Write Symbol Table
    fseek(file, header->PointerToSymbolTable, SEEK_SET);
    fwrite(symbols, 1, sizeof(COFF_SYMBOL) * numSymbols, file);

    // Write String Table
    fwrite(&stringTableSize, 1, sizeof(uint32_t), file);
    fwrite(stringTable, 1, stringTableSize, file);

    fclose(file);
    return 0;
}


void print_coff_header(COFF_HEADER *header) {
    printf("COFF Header:\n");
    printf("  Machine: 0x%04X ", header->Machine);
    switch (header->Machine) {
        case 0x014C: printf("(Intel 386)\n"); break;
        case 0x8664: printf("(AMD64)\n"); break;
        case 0x0200: printf("(Intel Itanium)\n"); break;
        default: printf("(Unknown)\n"); break;
    }
    printf("  Number of Sections: %d\n", header->NumberOfSections);
    printf("  Time Date Stamp: 0x%08X\n", header->TimeDateStamp);
    printf("  Pointer to Symbol Table: 0x%08X\n", header->PointerToSymbolTable);
    printf("  Number of Symbols: %d\n", header->NumberOfSymbols);
    printf("  Size of Optional Header: %d\n", header->SizeOfOptionalHeader);
    printf("  Characteristics: 0x%04X ", header->Characteristics);
    if (header->Characteristics & 0x0002) printf("(Executable Image) ");
    if (header->Characteristics & 0x2000) printf("(Relocation info stripped from file) ");
    printf("\n");
}

// Function to print section header information
void print_section_header(SECTION_HEADER *section) {
    printf("Section Header:\n");
    printf("  Name: %.8s\n", section->Name);
    printf("  Virtual Size: 0x%08X\n", section->VirtualSize);
    printf("  Virtual Address: 0x%08X\n", section->VirtualAddress);
    printf("  Size of Raw Data: 0x%08X\n", section->SizeOfRawData);
    printf("  Pointer to Raw Data: 0x%08X\n", section->PointerToRawData);
    printf("  Pointer to Relocations: 0x%08X\n", section->PointerToRelocations);
    printf("  Pointer to Line Numbers: 0x%08X\n", section->PointerToLinenumbers);
    printf("  Number of Relocations: %d\n", section->NumberOfRelocations);
    printf("  Number of Line Numbers: %d\n", section->NumberOfLinenumbers);
    printf("  Characteristics: 0x%08X ", section->Characteristics);

    // More detailed output about section characteristics
    if (section->Characteristics & 0x00000020) printf("(Contains executable code) ");
    if (section->Characteristics & 0x40000000) printf("(Initialized data) ");
    if (section->Characteristics & 0x80000000) printf("(Uninitialized data) ");
    if (section->Characteristics & 0x20000000) printf("(Contains comments or other non-linked data) ");

    printf("\n");
}


// Function to print symbol table entry information
void print_symbol(COFF_SYMBOL *symbol, char *string_table) {
    printf("Symbol:\n");
    if (symbol->Name.ShortName[0] == 0) {
        printf("  Name: %s\n", string_table + symbol->Name.LongName.Offset);
    } else {
        printf("  Name: %.8s\n", symbol->Name.ShortName);
    }
    printf("  Value: 0x%08X\n", symbol->Value);
    printf("  Section Number: %d\n", symbol->SectionNumber);
    printf("  Type: 0x%04X\n", symbol->Type);
    printf("  Storage Class: 0x%02X ", symbol->StorageClass);
    switch (symbol->StorageClass) {
        case 2: printf("(External)\n"); break;
        case 3: printf("(Static)\n"); break;
        case 6: printf("(Function)\n"); break;
        default: printf("(Unknown)\n"); break;
    }
    printf("  Number of Aux Symbols: %d\n", symbol->NumberOfAuxSymbols);
}

// Function to read section raw data and output some bytes as code preview
void print_section_code_preview(FILE *file, SECTION_HEADER *section) {
    if (section->SizeOfRawData > 0) {
        printf("Code Preview (first 32 bytes):\n");
        unsigned char *buffer = malloc(section->SizeOfRawData);
        if (!buffer) {
            perror("Failed to allocate memory for section data");
            return;
        }

        fseek(file, section->PointerToRawData, SEEK_SET);
        fread(buffer, 1, section->SizeOfRawData, file);

        for (uint32_t i = 0; i < (section->SizeOfRawData > 32 ? 32 : section->SizeOfRawData); i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");

        free(buffer);
    } else {
        printf("Section has no raw data.\n");
    }
}