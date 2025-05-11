#include <stdio.h>
#include <stdlib.h>
#include "LibELFparse.h"

void print_f(const char *s, void *u) {
    printf("  %s\n", s);
}



void show_elf_info(const ElfFile *elf) {
    printf("ELF Class: %s\n", elf->elf_class==ELFCLASS_32 ? "ELF32" : "ELF64");
    printf("Secciones:\n");
    for (size_t i=0; i<elf_section_count(elf); ++i) {
        printf("  %2zu: %-20s Tipo: %u Addr: 0x%lx Offset: 0x%lx Size: 0x%lx\n",
            i, elf_section_name(elf, i), elf_section_type(elf, i),
            (unsigned long)elf_section_addr(elf, i),
            (unsigned long)elf_section_offset(elf, i),
            (unsigned long)elf_section_size(elf, i));
    }
    show_elf_code_data_sections_auto(elf);
    size_t symtab_idx;
    size_t nsym = elf_symbol_count(elf, &symtab_idx);
    if (nsym) {
        printf("\nSimbolos:\n");
        for (size_t i=0; i<nsym; ++i) {
            uint8_t info = elf_symbol_info(elf, symtab_idx, i);
            printf("  %3zu: %-30s 0x%lx Info: 0x%02x [%s|%s]\n",
                i, elf_symbol_name(elf, symtab_idx, i),
                (unsigned long)elf_symbol_value(elf, symtab_idx, i),
                info, sym_type_str(info), sym_bind_str(info));
        }
    }
    // Relocaciones extendidas
    printf("\nRelocaciones:\n");
    for (size_t i=0; i<elf_section_count(elf); ++i) {
        if (elf_section_type(elf, i)==SHT_REL || elf_section_type(elf, i)==SHT_RELA) {
            size_t nrel = elf_relocation_count(elf, i);
            for (size_t j=0; j<nrel; ++j) {
                uint64_t off; uint32_t type; int sym;
                elf_get_relocation(elf, i, j, &off, &type, &sym);
                printf("  Seccion %zu Rel %zu: Offset 0x%lx Type %u Sym %d\n", i, j, (unsigned long)off, type, sym);
            }
        }
    }

    // Librerias requeridas
    printf("\nLibrerias requeridas:\n");
    size_t nlib = elf_needed_count(elf);
    for (size_t i=0; i<nlib; ++i)
        printf("  %s\n", elf_needed_name(elf, i));

    printf("\nStrings de tablas de cadenas:\n");
    elf_iterate_strings(elf, print_f, NULL);

    // Dynamic
    show_elf_dynamic(elf);

    // Notas
    show_elf_notes(elf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Uso: %s archivo_elf\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *mem = malloc(fsize);
    fread(mem, 1, fsize, f);
    fclose(f);

    ElfFile elf;
    if (!elf_mem_parse(&elf, mem, fsize)) {
        printf("No es un ELF válido\n");
        free(mem);
        return 1;
    }
    show_elf_info(&elf);

    free(mem);
    return 0;
}
