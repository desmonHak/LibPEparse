#include  "LibCOFFparse.h"

#include <time.h>

/*
 * gcc coff2.c -o coff2.exe
 * coff2.exe
 * gcc coff2linked.c add.obj -o coff2addlinker.exe
 * coff2addlinker.exe
*/

int main() {
    // 1. Define COFF Header
    COFF_HEADER header = {
        .Machine = 0x8664,          // AMD64
        .NumberOfSections = 1,       // One section for code
        .TimeDateStamp = time(NULL),
        .PointerToSymbolTable = 0,   // Will be calculated later
        .NumberOfSymbols = 1,        // Will be calculated later
        .SizeOfOptionalHeader = 0,
        .Characteristics = 0x0000    // It is an object file so no need to be an executable
    };

    // 2. Define Sections
    NewSection newSections[1];
    SECTION_HEADER sections[1];

    // Section 1: .text (Code)
    strcpy(newSections[0].name, ".text");
    newSections[0].characteristics = 0x60500020; // Code, Executable, Readable, 16-byte align

    uint8_t shellcode[] = {
        0x01, 0xd1, 0x89, 0xc8, 0xc3, 
    };

    // Define the 'add' function (x64 calling convention)
    newSections[0].data.data = shellcode;
    /*
     * add ecx, edx
     * mov eax, ecx
     * ret
    */
    newSections[0].data.size = sizeof(shellcode);
    newSections[0].relocations = NULL;
    newSections[0].numRelocations = 0;

    strcpy(sections[0].Name, ".text");
    sections[0].VirtualSize = newSections[0].data.size;
    sections[0].VirtualAddress = 0;  // This should be 0 for object files
    sections[0].SizeOfRawData = align(newSections[0].data.size, 16);  // Align to 16 bytes
    sections[0].PointerToRawData = align(sizeof(COFF_HEADER) + sizeof(SECTION_HEADER), 16);
    sections[0].PointerToRelocations = 0;
    sections[0].PointerToLinenumbers = 0;
    sections[0].NumberOfRelocations = 0;
    sections[0].NumberOfLinenumbers = 0;
    sections[0].Characteristics = newSections[0].characteristics;

    // 3. Define Symbols
    const int numSymbols = 1;
    COFF_SYMBOL symbols[numSymbols];

    // 'add' Function Symbol
    strcpy(symbols[0].Name.ShortName, "add");
    symbols[0].Value = 0;   // Offset within the section
    symbols[0].SectionNumber = 1;    // Section number
    symbols[0].Type = 0x20;          // Function type
    symbols[0].StorageClass = 2;     // External
    symbols[0].NumberOfAuxSymbols = 0;

    header.NumberOfSymbols = numSymbols;

    // 4. Define String Table
    char stringTable[256] = { 0 };
    uint32_t stringTableSize = 4; // Minimum size (size field itself)

    // Add symbol names to the string table
    strcpy(stringTable + stringTableSize, "add");
    stringTableSize += strlen("add") + 1;

    // 5. Calculate Offsets
    header.PointerToSymbolTable = sections[0].PointerToRawData + sections[0].SizeOfRawData;

    // 6. Write COFF File
    create_coff_file(
        "add.obj", &header, sections, 
        newSections, header.NumberOfSections, symbols, 
        header.NumberOfSymbols, stringTable, stringTableSize);

    return 0;
}
