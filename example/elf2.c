#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

uint8_t code[] = {
    0x48, 0xbf, 0,0,0,0, 0,0,0,0, // movabs rdi, <str_addr>
    0xe8, 0,0,0,0,                // call printf@plt (relativo)
    0x31, 0xff,                   // xor edi, edi
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
    0x0f, 0x05                    // syscall
};

const char hello_str[] = "Hola mundo\n";
const char interp_path[] = "/lib64/ld-linux-x86-64.so.2";

#define PAGE_SIZE 0x1000
#define ALIGN(x, a) (((x) + ((a)-1)) & ~((a)-1))

int main() {
    // Offsets y direcciones base
    uint64_t base_vaddr = 0x400000;
    size_t interp_off = 0x200;
    size_t text_off = 0x1000;
    size_t data_off = 0x2000;
    size_t plt_off = 0x3000;
    size_t gotplt_off = 0x4000;
    size_t dynstr_off = 0x5000;
    size_t dynsym_off = 0x6000;
    size_t rela_plt_off = 0x7000;
    size_t dynamic_off = 0x8000;

    // Crear ELF
    size_t capacity = 0x10000;
    ElfBuilder *b = elf_builder_create_exec64(capacity);

    // .interp
    elf_builder_add_section(b, ".interp", SHT_PROGBITS, SHF_ALLOC,
        interp_path, strlen(interp_path)+1, base_vaddr+interp_off, 1, NULL, NULL);

    // .text
    if (text_off > b->size) memset(b->mem + b->size, 0, text_off - b->size), b->size = text_off;
    size_t text_section_off;
    uint64_t text_section_vaddr;
    elf_builder_add_section(b, ".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
        code, sizeof(code), base_vaddr+text_off, 16, &text_section_off, &text_section_vaddr);

    // .data
    if (data_off > b->size) memset(b->mem + b->size, 0, data_off - b->size), b->size = data_off;
    size_t data_section_off;
    uint64_t data_section_vaddr;
    elf_builder_add_section(b, ".data", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
        hello_str, sizeof(hello_str), base_vaddr+data_off, 8, &data_section_off, &data_section_vaddr);

    // .plt (solo una entrada para printf)
    uint8_t plt[0x10] = {
        0xff, 0x25, 0,0,0,0,             // jmpq *got+8(%rip)
        0x68, 0,0,0,0,                   // pushq reloc_index (0)
        0xe9, 0,0,0,0                    // jmp plt[0]
    };
    uint64_t gotplt_addr = base_vaddr + gotplt_off;
    uint64_t plt_addr = base_vaddr + plt_off;
    *(uint32_t*)&plt[2] = (uint32_t)(gotplt_addr + 8 - (plt_addr + 6));
    *(uint32_t*)&plt[7] = 0; // reloc_index
    *(uint32_t*)&plt[12] = (uint32_t)(plt_addr - (plt_addr + 16));
    elf_builder_add_section(b, ".plt", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
        plt, sizeof(plt), plt_addr, 16, NULL, NULL);

    // .got.plt (solo para printf)
    uint64_t gotplt[2] = {0};
    elf_builder_add_section(b, ".got.plt", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
        gotplt, sizeof(gotplt), gotplt_addr, 8, NULL, NULL);

    // .dynstr
    char dynstr[16] = "\0printf\0";
    elf_builder_add_section(b, ".dynstr", SHT_STRTAB, SHF_ALLOC,
        dynstr, sizeof(dynstr), base_vaddr+dynstr_off, 1, NULL, NULL);

    // .dynsym
    struct {
        uint32_t st_name; uint8_t st_info, st_other; uint16_t st_shndx;
        uint64_t st_value, st_size;
    } dynsym[2] = {0};
    dynsym[1].st_name = 1; // offset en dynstr
    dynsym[1].st_info = 0x12; // GLOBAL FUNC
    elf_builder_add_section(b, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
        dynsym, sizeof(dynsym), base_vaddr+dynsym_off, 8, NULL, NULL);

    // .rela.plt
    struct { uint64_t r_offset, r_info; int64_t r_addend; } rela_plt[1];
    rela_plt[0].r_offset = gotplt_addr + 8;
    rela_plt[0].r_info = ((1ULL)<<32) | 0x7; // símbolo 1, tipo JMP_SLOT
    rela_plt[0].r_addend = 0;
    elf_builder_add_section(b, ".rela.plt", SHT_RELA, SHF_ALLOC,
        rela_plt, sizeof(rela_plt), base_vaddr+rela_plt_off, 8, NULL, NULL);

    // .dynamic
    struct { int64_t tag; uint64_t val; } dynamic[] = {
        {1, base_vaddr+dynstr_off},      // DT_STRTAB
        {5, base_vaddr+dynsym_off},      // DT_SYMTAB
        {6, sizeof(dynsym[0])},          // DT_SYMENT
        {0x17, base_vaddr+rela_plt_off}, // DT_JMPREL
        {0x7, sizeof(rela_plt)},         // DT_PLTRELSZ
        {0x2, 0x7},                      // DT_PLTREL (RELA)
        {0xf, gotplt_addr},              // DT_PLTGOT
        {0x1d, base_vaddr+plt_off},      // DT_PLT
        {0x1e, sizeof(plt)},             // DT_PLTSZ
        {0xe, 1},                        // DT_SONAME (dummy)
        {0x0, 0}                         // DT_NULL
    };
    elf_builder_add_section(b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE,
        dynamic, sizeof(dynamic), base_vaddr+dynamic_off, 8, NULL, NULL);

    // --- Parchear el código ---
    *(uint64_t *)(b->mem + text_section_off + 2) = data_section_vaddr;
    uint64_t rip_after_call = text_section_vaddr + 11;
    int32_t rel = (int32_t)(plt_addr - rip_after_call);
    *(int32_t *)(b->mem + text_section_off + 10) = rel;

    // --- Finalizar ELF ---
    elf_builder_finalize_exec64(
        b,
        text_section_vaddr, // entry point
        text_section_off,
        text_section_vaddr,
        sizeof(code)
    );

    // --- Escribir a disco ---
    FILE *f = fopen("salida_printf.elf", "wb");
    fwrite(b->mem, 1, b->size, f);
    fclose(f);

    printf("ELF ejecutable generado: salida_printf.elf (%zu bytes)\n", b->size);
    printf("chmod +x salida_printf.elf && ./salida_printf.elf\n");

    elf_builder_free(b);
    return 0;
}
