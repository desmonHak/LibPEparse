#include <stdio.h>
#include <stdlib.h>
#include "LibELFparse.h"






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
