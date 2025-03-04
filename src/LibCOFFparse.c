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

    // Write COFF header
    fwrite(header, 1, sizeof(COFF_HEADER), file);

    // Write section headers
    fwrite(sections, 1, sizeof(SECTION_HEADER) * numSections, file);

    // Write section data and padding
    for (int i = 0; i < numSections; i++) {
        fseek(file, sections[i].PointerToRawData, SEEK_SET);
        fwrite(newSections[i].data.data, 1, newSections[i].data.size, file);

        // Pad the section with zeros to SizeOfRawData
        uint32_t paddingSize = sections[i].SizeOfRawData - newSections[i].data.size;
        char* padding = calloc(1, paddingSize);  // Initialize padding with zeros
        fwrite(padding, 1, paddingSize, file);
        free(padding);
    }

    // Write relocations
    for (int i = 0; i < numSections; i++) {
        if (newSections[i].numRelocations > 0) {
            fseek(file, sections[i].PointerToRelocations, SEEK_SET);
            fwrite(newSections[i].relocations, 1, newSections[i].numRelocations * sizeof(RELOCATION), file);
        }
    }

    // Write symbol table
    fseek(file, header->PointerToSymbolTable, SEEK_SET);
    fwrite(symbols, 1, sizeof(COFF_SYMBOL) * numSymbols, file);

    // Write string table
    fseek(file, header->PointerToSymbolTable + sizeof(COFF_SYMBOL) * numSymbols, SEEK_SET);
    fwrite(&stringTableSize, 1, sizeof(uint32_t), file);
    fwrite(stringTable + 4, 1, stringTableSize - 4, file);

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

    if (section->Characteristics & 0x00000020) printf("(Contains executable code) ");
    if (section->Characteristics & 0x40000000) printf("(Initialized data) ");
    if (section->Characteristics & 0x80000000) printf("(Uninitialized data) ");
    if (section->Characteristics & 0x20000000) printf("(Contains comments or other non-linked data) ");

    printf("\n");
}

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

NewSection create_section(const char* name, uint32_t characteristics, const void* data, size_t size, RELOCATION* relocations, int numRelocations) {
    NewSection section;
    strncpy(section.name, name, 8);
    section.name[8] = '\0';
    section.characteristics = characteristics;
    section.data.size = size;
    section.data.data = malloc(size);
    memcpy(section.data.data, data, size);
    section.relocations = relocations;
    section.numRelocations = numRelocations;
    return section;
}

COFF_SYMBOL create_symbol(const char* name, uint32_t value, int16_t section_number, uint16_t type, uint8_t storage_class) {
    COFF_SYMBOL symbol = {0};
    if (strlen(name) > 8) {
        symbol.Name.LongName.Zero = 0;
        // Offset en la tabla de strings se ajustará al escribir
        symbol.Name.LongName.Offset = 4;  // inicio de los nombres en la tabla
    } else {
        strncpy(symbol.Name.ShortName, name, 8);
        symbol.Name.ShortName[8] = '\0'; // Ensure null termination
    }
    symbol.Value = value;
    symbol.SectionNumber = section_number;
    symbol.Type = type;
    symbol.StorageClass = storage_class;
    symbol.NumberOfAuxSymbols = 0;
    return symbol;
}


void setup_sections(SECTION_HEADER* sections, NewSection* newSections, int num_sections) {
    uint32_t current_offset = align(sizeof(COFF_HEADER) + num_sections * sizeof(SECTION_HEADER), 16);
    uint32_t current_virtual_address = 0x1000;  // Dirección virtual base

    for (int i = 0; i < num_sections; i++) {
        strncpy(sections[i].Name, newSections[i].name, 8);
        sections[i].Name[8] = '\0'; // Ensure null termination
        sections[i].VirtualSize = newSections[i].data.size;
        sections[i].VirtualAddress = current_virtual_address;
        sections[i].SizeOfRawData = align(newSections[i].data.size, 16);
        sections[i].PointerToRawData = align(current_offset, 16);  // Asegura alineación de 16 bytes
        sections[i].PointerToRelocations = current_offset + sections[i].SizeOfRawData;
        sections[i].PointerToLinenumbers = 0;
        sections[i].NumberOfRelocations = newSections[i].numRelocations;
        sections[i].NumberOfLinenumbers = 0;
        sections[i].Characteristics = newSections[i].characteristics;
        current_offset = align(sections[i].PointerToRelocations + newSections[i].numRelocations * sizeof(RELOCATION), 16);
        current_virtual_address += align(newSections[i].data.size, 16); // Incrementa la dirección virtual
    }
}


RELOCATION create_relocation(uint32_t offset, uint32_t symbol_index, uint16_t type) {
    RELOCATION reloc;
    reloc.VirtualAddress = offset;
    reloc.SymbolTableIndex = symbol_index;
    reloc.Type = type;
    return reloc;
}

void add_relocation(NewSection* section, RELOCATION reloc) {
    if (section->relocations == NULL) {
        section->relocations = malloc(sizeof(RELOCATION));
        if (!section->relocations) {
            perror("Failed to allocate memory for relocation");
            exit(1);
        }
        section->relocations[0] = reloc;
        section->numRelocations = 1;
    } else {
        section->relocations = realloc(section->relocations, (section->numRelocations + 1) * sizeof(RELOCATION));
        if (!section->relocations) {
            perror("Failed to reallocate memory for relocation");
            exit(1);
        }
        section->relocations[section->numRelocations] = reloc;
        section->numRelocations++;
    }
}


void print_relocation(RELOCATION *reloc) {
    printf("Relocation:\n");
    printf("  Virtual Address: 0x%08X\n", reloc->VirtualAddress);
    printf("  Symbol Table Index: %d\n", reloc->SymbolTableIndex);
    printf("  Type: 0x%04X\n", reloc->Type);
}

void print_coff_info(COFF_HEADER *header, SECTION_HEADER *sections, NewSection *newSections, COFF_SYMBOL *symbols, char *stringTable, uint32_t stringTableSize) {
    print_coff_header(header);
    
    for (int i = 0; i < header->NumberOfSections; i++) {
        printf("\n");
        print_section_header(&sections[i]);
        printf("Section Data:\n");
        for (size_t j = 0; j < newSections[i].data.size; j++) {
            printf("%02X ", (unsigned char)newSections[i].data.data[j]);
            if ((j + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
        
        for (int j = 0; j < newSections[i].numRelocations; j++) {
            print_relocation(&newSections[i].relocations[j]);
        }
    }
    
    printf("\nSymbols:\n");
    for (uint32_t i = 0; i < header->NumberOfSymbols; i++) {
        print_symbol(&symbols[i], stringTable);
    }
    
    printf("\nString Table:\n");
    for (uint32_t i = 4; i < stringTableSize; i++) {
        if (stringTable[i] == '\0') {
            printf("\\0");
        } else {
            printf("%c", stringTable[i]);
        }
    }
    printf("\n");
}
uint32_t calculate_symbol_table_offset(SECTION_HEADER* section_headers, int num_sections) {
    uint32_t offset = sizeof(COFF_HEADER) + num_sections * sizeof(SECTION_HEADER);
    for (int i = 0; i < num_sections; ++i) {
        offset = align(offset, 16);
        offset += section_headers[i].SizeOfRawData;
        offset = align(offset, 16);
        offset += section_headers[i].NumberOfRelocations * sizeof(RELOCATION);
    }
    return offset;
}

void cleanup_resources(NewSection* sections, int num_sections) {
    for (int i = 0; i < num_sections; ++i) {
        if (sections[i].relocations) free(sections[i].relocations);
        free(sections[i].data.data);
    }
}
