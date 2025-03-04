#include  "./src/LibCOFFparse.c"
// gcc coff3.c -o coff3.exe
// coff3.exe
// objdump -s -j .data add.obj
// gcc coff2linked.c add.obj -o coff3addlinker.exe

#define NUM_SECTIONS 2
#define NUM_SYMBOLS 3

int main() {
    COFF_HEADER header = {
        .Machine = 0x8664,
        .NumberOfSections = NUM_SECTIONS,
        .TimeDateStamp = time(NULL),
        .NumberOfSymbols = NUM_SYMBOLS,
        .SizeOfOptionalHeader = 0,
        .Characteristics = 0x0000
    };

    uint8_t shellcode[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x90,
        0x48, 0xC7, 0xC2, 0x0A, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0xC3
    };

    uint8_t dataContent[] = "Hola mundo %d\n";

    NewSection sections[NUM_SECTIONS] = {
        [0] = create_section(".text", IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, shellcode, sizeof(shellcode), NULL, 0),
        [1] = create_section(".data", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, dataContent, sizeof(dataContent), NULL, 0)
    };

    uint32_t printf_reloc_offset = 8;  // Offset de la instrucción mov rax, imm64
    uint32_t format_string_reloc_offset = 24;  // Offset de la instrucción lea rcx, [rip+disp32]

    add_relocation(&sections[0], create_relocation(printf_reloc_offset, 1, IMAGE_REL_AMD64_ADDR64));
    add_relocation(&sections[0], create_relocation(format_string_reloc_offset, 0, IMAGE_REL_AMD64_REL32));


    SECTION_HEADER section_headers[NUM_SECTIONS];
    setup_sections(section_headers, sections, NUM_SECTIONS);

    COFF_SYMBOL symbols[NUM_SYMBOLS] = {
        [0] = create_symbol("_formatString", section_headers[1].VirtualAddress, 2, 0, 3),
        [1] = create_symbol("printf", 0, 0, 0x20, 2),
        [2] = create_symbol("add", section_headers[0].VirtualAddress, 1, 0x20, 2)
    };

    char stringTable[256] = {0};
    uint32_t stringTableSize = 4;
    const char* symbolNames[NUM_SYMBOLS] = {"_formatString", "printf", "add"};

    for (int i = 0; i < NUM_SYMBOLS; i++) {
        strcpy(stringTable + stringTableSize, symbolNames[i]);
        stringTableSize += strlen(symbolNames[i]) + 1;
    }

    header.PointerToSymbolTable = calculate_symbol_table_offset(section_headers, NUM_SECTIONS);

    print_coff_info(&header, section_headers, sections, symbols, stringTable, stringTableSize);

    if (create_coff_file("add.obj", &header, section_headers, sections, NUM_SECTIONS, symbols, NUM_SYMBOLS, stringTable, stringTableSize) != 0) {
        fprintf(stderr, "Error creating COFF file\n");
        return 1;
    }

    cleanup_resources(sections, NUM_SECTIONS);

    return 0;
}
