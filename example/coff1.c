#include  "LibCOFFparse.h"

int main() {
    // --- Example Usage ---

    // 1. Define COFF Header
    COFF_HEADER header = {
        .Machine = 0x8664,          // AMD64
        .NumberOfSections = 2,       // Example: Two sections
        .TimeDateStamp = time(NULL),
        .PointerToSymbolTable = 0,   // Will be calculated later
        .NumberOfSymbols = 0,        // Will be calculated later
        .SizeOfOptionalHeader = 0,
        .Characteristics = 0x0002    // Executable Image
    };

    // 2. Define Sections
    NewSection newSections[2];
    SECTION_HEADER sections[2];

    // Section 1: .text (Code)
    strcpy(newSections[0].name, ".text");
    newSections[0].characteristics = 0x60000020; // Code, Executable, Readable
    newSections[0].data.data = "\x48\x31\xC0\xC3"; // Example code: xor rax, rax; ret
    newSections[0].data.size = 4;
    newSections[0].relocations = NULL;
    newSections[0].numRelocations = 0;

    strcpy(sections[0].Name, ".text");
    sections[0].VirtualSize = newSections[0].data.size;
    sections[0].VirtualAddress = 0x1000;
    sections[0].SizeOfRawData = align(newSections[0].data.size, 512);
    sections[0].PointerToRawData = 512;
    sections[0].PointerToRelocations = 0;
    sections[0].PointerToLinenumbers = 0;
    sections[0].NumberOfRelocations = 0;
    sections[0].NumberOfLinenumbers = 0;
    sections[0].Characteristics = newSections[0].characteristics;

    // Section 2: .data (Data)
    strcpy(newSections[1].name, ".data");
    newSections[1].characteristics = 0xC0000040; // Initialized Data, Readable, Writable
    newSections[1].data.data = "Hello, COFF!";
    newSections[1].data.size = strlen(newSections[1].data.data) + 1;
    newSections[1].relocations = NULL;
    newSections[1].numRelocations = 0;

    strcpy(sections[1].Name, ".data");
    sections[1].VirtualSize = newSections[1].data.size;
    sections[1].VirtualAddress = 0x2000;
    sections[1].SizeOfRawData = align(newSections[1].data.size, 512);
    sections[1].PointerToRawData = 1024;
    sections[1].PointerToRelocations = 0;
    sections[1].PointerToLinenumbers = 0;
    sections[1].NumberOfRelocations = 0;
    sections[1].NumberOfLinenumbers = 0;
    sections[1].Characteristics = newSections[1].characteristics;

    // 3. Define Symbols
    COFF_SYMBOL symbols[1];
    strcpy(symbols[0].Name.ShortName, "main");
    symbols[0].Value = sections[0].VirtualAddress;
    symbols[0].SectionNumber = 1; // Section number 1 (.text)
    symbols[0].Type = 0;
    symbols[0].StorageClass = 2; // External
    symbols[0].NumberOfAuxSymbols = 0;

    header.NumberOfSymbols = 1;

    // 4. Define String Table
    char stringTable[256] = { 0 };
    uint32_t stringTableSize = 4; // Minimum size (size field itself)
    strcpy(stringTable + stringTableSize, "main");
    stringTableSize += strlen("main") + 1;

    header.PointerToSymbolTable = 1024 + sections[0].SizeOfRawData + sections[1].SizeOfRawData;
    header.NumberOfSymbols = 1;

    // Write COFF File
    create_coff_file("my_coff_file.obj", &header, sections, newSections, header.NumberOfSections, symbols, header.NumberOfSymbols, stringTable, stringTableSize);

    // Optional: Parse and print the created COFF file
    FILE* parsedFile = fopen("my_coff_file.obj", "rb");
    if (parsedFile) {
        COFF_HEADER parsedHeader;
        fread(&parsedHeader, sizeof(COFF_HEADER), 1, parsedFile);
        print_coff_header(&parsedHeader);

        SECTION_HEADER* parsedSections = malloc(sizeof(SECTION_HEADER) * parsedHeader.NumberOfSections);
        fread(parsedSections, sizeof(SECTION_HEADER), parsedHeader.NumberOfSections, parsedFile);
        for (int i = 0; i < parsedHeader.NumberOfSections; i++) {
            print_section_header(&parsedSections[i]);
        }

         if (parsedHeader.PointerToSymbolTable) {
        fseek(parsedFile, parsedHeader.PointerToSymbolTable, SEEK_SET);

        COFF_SYMBOL *parsedSymbols = malloc(sizeof(COFF_SYMBOL) * parsedHeader.NumberOfSymbols);
        if (!parsedSymbols) {
            perror("Error allocating memory for symbols");
            free(parsedSections);
            fclose(parsedFile);
            return 1;
        }

        if (fread(parsedSymbols, sizeof(COFF_SYMBOL), parsedHeader.NumberOfSymbols, parsedFile) != parsedHeader.NumberOfSymbols) {
            perror("Error reading symbols");
            free(parsedSymbols);
            free(parsedSections);
            fclose(parsedFile);
            return 1;
        }

        char *parsedString_table = NULL;
        uint32_t parsedString_table_size;
        if (fread(&parsedString_table_size, sizeof(uint32_t), 1, parsedFile) == 1) {
             parsedString_table = malloc(parsedString_table_size);
            if (!parsedString_table) {
                perror("Error allocating memory for string table");
                free(parsedSymbols);
                free(parsedSections);
                fclose(parsedFile);
                return 1;
            }
             if (fread(parsedString_table + 4, 1, parsedString_table_size - 4, parsedFile) != parsedString_table_size - 4) {
                perror("Error reading string table");
                free(parsedString_table);
                free(parsedSymbols);
                free(parsedSections);
                fclose(parsedFile);
                return 1;
            }
        }

        for (uint32_t i = 0; i < parsedHeader.NumberOfSymbols; i++) {
            printf("\n");
            print_symbol(&parsedSymbols[i], parsedString_table);
           // i += parsedSymbols[i].NumberOfAuxSymbols;
        }

        free( parsedString_table);
        free(parsedSymbols);
    }
        free(parsedSections);
        fclose(parsedFile);
    }
}
