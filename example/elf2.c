#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "CreateELF.h"
#include "LibELFparse.h"

#define PAGE_SIZE 0x1000

uint8_t exit_program[] = {
    // mov rax, 0x0a646c726f77
    0x48, 0xb8, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00, 0x00, // Corrected: 0x0a for newline, then "world"
    0x50,                               // push rax

    // mov rax, 0x202c6f6c6c6548
    0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x00, // "Hello, "
    0x50,                               // push rax
    // mov rsi, rsp
    0x48, 0x89, 0xe6,

    // mov rdx, 13 (length of "Hello, world\n")
    0xba, 0x0d, 0x00, 0x00, 0x00,

    // mov rdi, 1 (stdout)
    0xbf, 0x01, 0x00, 0x00, 0x00,

    // mov rax, 1 (sys_write)
    0xb8, 0x01, 0x00, 0x00, 0x00,

    // syscall
    0x0f, 0x05,

    // xor edi, edi (exit status 0)
    0x31, 0xff,

    // mov eax, 60 (sys_exit)
    0xb8, 0x3c, 0x00, 0x00, 0x00,

    // syscall
    0x0f, 0x05
};

int main() {
    size_t code_size = sizeof(exit_program);
    uint64_t base_vaddr = 0x400000; // Typical start address for code after headers
    size_t code_file_off = 0x1000; // Offset for code in the file

    // Allocate enough capacity. Ensure it's large enough for headers, code, and section headers.
    // We'll have two program headers for code/data and stack.
    size_t capacity = 16 * PAGE_SIZE;
    ElfBuilder *b = elf_builder_create_exec64(capacity, 2);
    if (!b) {
        fprintf(stderr, "No se pudo crear el ElfBuilder\n");
        return 1;
    }
    // Program headers are placed immediately after Elf64_Ehdr.
    // `b->phdr` already points to this memory location within `b->mem`.
    Elf64_Phdr *phdr = (Elf64_Phdr *)b->phdr;

    // Align the start of the .text section to a new page in the file.
    // This is where the actual code content will begin after ELF and program headers.
    if (b->size % PAGE_SIZE != 0) {
        size_t padding = PAGE_SIZE - (b->size % PAGE_SIZE);
        memset(b->mem + b->size, 0, padding);
        b->size += padding;
    }
    code_file_off = b->size; // Update code_file_off to the aligned position


    // Add the .text section with the executable code
    size_t text_section_off;
    uint64_t text_section_vaddr;
    size_t idx_text = elf_builder_add_section_ex(b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                                              exit_program, code_size, base_vaddr + code_file_off, PAGE_SIZE,
                                              &text_section_off, &text_section_vaddr,
                                              0, 0, 0);
    if (idx_text == 0) { // elf_builder_add_section returns 0 on failure
        fprintf(stderr, "Error al añadir la sección .text\n");
        elf_builder_free(b);
        return 1;
    }

    // Add .strtab (string table for symbol names)
    // Contains "_start"
    const char strtab_data[] = "\0_start\0"; // Needs null byte at beginning and after "_start"
    size_t strtab_data_size = sizeof(strtab_data);
    size_t strtab_section_off;
    uint64_t strtab_section_vaddr;
    size_t idx_strtab = elf_builder_add_section_ex(
        b, ".strtab", SHT_STRTAB, 0,
        strtab_data, strtab_data_size,
        0, 1, // Vaddr 0, alignment 1
        &strtab_section_off, &strtab_section_vaddr,
        0, 0, 0
    );
    if (idx_strtab == 0) {
        fprintf(stderr, "Error al añadir la sección .strtab\n");
        elf_builder_free(b);
        return 1;
    }

    // Add .symtab (symbol table)
    // Contains the "_start" symbol pointing to the entry point
    Elf64_Sym symtab[2] = {0};
    // Null symbol (mandatory first entry)
    symtab[0].st_name = 0;
    symtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    symtab[0].st_shndx = SHN_UNDEF;
    // _start symbol
    symtab[1].st_name = 1; // Offset of "_start" in .strtab (after initial null byte)
    symtab[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); // Global, Function type
    symtab[1].st_shndx = idx_text; // Points to .text section
    symtab[1].st_value = text_section_vaddr; // Virtual address of the entry point
    symtab[1].st_size = code_size; // Size of the function

    size_t symtab_section_off;
    uint64_t symtab_section_vaddr;
    size_t idx_symtab = elf_builder_add_section_ex(
        b, ".symtab", SHT_SYMTAB, 0,
        symtab, sizeof(symtab),
        0, 8, // Vaddr 0, alignment 8
        &symtab_section_off, &symtab_section_vaddr,
        idx_strtab, 1, sizeof(Elf64_Sym) // Link to .strtab, first local symbol is 1, entry size
    );
    if (idx_symtab == 0) {
        fprintf(stderr, "Error al añadir la sección .symtab\n");
        elf_builder_free(b);
        return 1;
    }

    // --- Configure Program Headers ---
    // The `b->phnum` was already set to 2.

    // Program Header 0: Executable segment (covers ELF header, program headers, .text section)
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_X; // Read, Execute
    phdr[0].p_offset = 0; // Starts from the beginning of the file
    phdr[0].p_vaddr = base_vaddr; // Virtual address for loading (same as base_vaddr)
    phdr[0].p_paddr = base_vaddr; // Physical address (for systems that care, typically same as vaddr)
    // file size = current size of the ELF file up to the end of the .text section data
    phdr[0].p_filesz = b->size; // All file data up to this point
    // memory size = filesz, rounded up to page alignment
    phdr[0].p_memsz = (b->size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    phdr[0].p_align = PAGE_SIZE;

    // Program Header 1: Segmento de pila (Read/Write, not file-backed)
    // Esta direccion de pila, debe estar en direcciones altas,
    // nada asegura que el programa vaya a tener esta direccion, pues lo
    // decide el kernel, pero se puede sugerir de esta manera una direccion
    // en especifico.
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W; // Read, Write
    phdr[1].p_offset = 0; // Not file-backed (size is 0)
    phdr[1].p_vaddr = 0x70000000; // A high virtual address for the stack
    phdr[1].p_paddr = 0x70000000;
    phdr[1].p_filesz = 0; // No file content
    phdr[1].p_memsz = 0x10000; // 64KB for stack (common size)
    phdr[1].p_align = PAGE_SIZE;


    // Finalize ELF header and place section header table
    // `text_section_vaddr` is the correct entry point
    elf_builder_finalize_exec64(b, text_section_vaddr);

    // Write to file
    FILE *f = fopen("salida_exec.elf", "wb");
    if (!f) {
        perror("Error al abrir el archivo de salida");
        elf_builder_free(b);
        return 1;
    }

    size_t written = fwrite(b->mem, 1, b->size, f);
    if (written != b->size) {
        perror("Error al escribir el archivo ELF");
        fclose(f);
        elf_builder_free(b);
        return 1;
    }

    fclose(f);
    printf("ELF ejecutable generado: salida_exec.elf (%zu bytes)\n", b->size);
    printf("Para hacer el archivo ejecutable: chmod +x salida_exec.elf\n");

    // Verify the generated ELF
    f = fopen("salida_exec.elf", "rb");
    if (!f) {
        perror("No se pudo abrir el archivo generado para verificación");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *mem = malloc(fsize);
    if (!mem) {
        perror("No se pudo asignar memoria para verificación");
        fclose(f);
        return 1;
    }

    if (fread(mem, 1, fsize, f) != fsize) {
        perror("Error al leer el archivo para verificación");
        free(mem);
        fclose(f);
        return 1;
    }

    fclose(f);

    ElfFile elf;
    if (!elf_mem_parse(&elf, mem, fsize)) {
        printf("El archivo generado no es un ELF válido\n");
        free(mem);
        return 1;
    }

    show_elf_info(&elf);
    free(mem);

    // Free resources
    elf_builder_free(b);

    return 0;
}