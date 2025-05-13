#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

#define PAGE_SIZE 0x1000

// Código ensamblador x86-64 para llamar a printf("Hola mundo\n")
uint8_t code[] = {
    0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string>
    0x31, 0xc0,                   // xor eax, eax
    0xe8, 0,0,0,0,                // call printf (offset relleno después)
    0x31, 0xff,                   // xor edi, edi
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
    0x0f, 0x05                    // syscall
};
const char hello_str[] = "Hola mundo\n";

int main() {
    size_t code_size = sizeof(code);
    size_t data_size = sizeof(hello_str);
    uint64_t base_vaddr = 0x400000;
    size_t text_file_off = 0x1000;
    size_t data_file_off = text_file_off + 0x1000;
    size_t capacity = 16 * PAGE_SIZE;
    ElfBuilder *b = elf_builder_create_exec64(capacity);
    if (!b) { fprintf(stderr, "No se pudo crear el ElfBuilder\n"); return 1; }
    if (text_file_off > b->size) {
        memset(b->mem + b->size, 0, text_file_off - b->size);
        b->size = text_file_off;
    }
    // .text
    size_t text_section_off; uint64_t text_section_vaddr;
    elf_builder_add_section(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        code, code_size, base_vaddr + text_file_off, 16,
        &text_section_off, &text_section_vaddr
    );
    if (data_file_off > b->size) {
        memset(b->mem + b->size, 0, data_file_off - b->size);
        b->size = data_file_off;
    }
    // .data
    size_t data_section_off; uint64_t data_section_vaddr;
    elf_builder_add_section(
        b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
        hello_str, data_size, base_vaddr + data_file_off, 8,
        &data_section_off, &data_section_vaddr
    );
    // Parchea dirección del string
    *(uint64_t *)(b->mem + text_section_off + 2) = data_section_vaddr;

    // --- Secciones dinámicas ---
    // .interp
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";
    size_t interp_off = b->size;
    memcpy(b->mem + interp_off, interp, sizeof(interp));
    b->size += sizeof(interp);

    // .dynstr
    const char dynstr[] = "\0printf\0libc.so.6\0";
    size_t dynstr_off = b->size;
    size_t dynstr_size = sizeof(dynstr);
    memcpy(b->mem + dynstr_off, dynstr, dynstr_size);
    b->size += dynstr_size;

    // .dynsym
    Elf64_Sym dynsym[2] = {0};
    dynsym[0].st_name = 0; // símbolo nulo
    dynsym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    dynsym[0].st_shndx = SHN_UNDEF;

    dynsym[1].st_name = 1; // offset en dynstr: "printf"
    dynsym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    dynsym[1].st_shndx = SHN_UNDEF;
    dynsym[1].st_value = 0;
    dynsym[1].st_size = 0;

    size_t dynsym_off = b->size;
    memcpy(b->mem + dynsym_off, dynsym, sizeof(dynsym));
    b->size += sizeof(dynsym);

    // .rela.plt
    Elf64_Rela rela = {0};
    rela.r_offset = text_section_vaddr + 13; // offset del call
    rela.r_info = ELF64_R_INFO(1, R_X86_64_JUMP_SLOT); // símbolo 1: printf
    rela.r_addend = 0;
    size_t rela_plt_off = b->size;
    memcpy(b->mem + rela_plt_off, &rela, sizeof(rela));
    b->size += sizeof(rela);

    // .got.plt
    uint64_t got_plt[3] = {0};
    size_t got_plt_off = b->size;
    memcpy(b->mem + got_plt_off, got_plt, sizeof(got_plt));
    b->size += sizeof(got_plt);

    // .dynamic
    Elf64_Dyn dynamic[] = {
        {DT_NEEDED, {dynstr_size - 9}}, // "libc.so.6" está al final de dynstr
        {DT_STRTAB, {base_vaddr + dynstr_off}},
        {DT_SYMTAB, {base_vaddr + dynsym_off}},
        {DT_RELA,   {base_vaddr + rela_plt_off}},
        {DT_RELASZ, {sizeof(rela)}},
        {DT_RELAENT, {sizeof(Elf64_Rela)}},
        {DT_STRSZ, {dynstr_size}},
        {DT_SYMENT, {sizeof(Elf64_Sym)}},
        {DT_PLTGOT, {base_vaddr + got_plt_off}},
        {DT_PLTRELSZ, {sizeof(rela)}},
        {DT_PLTREL, {DT_RELA}},
        {DT_JMPREL, {base_vaddr + rela_plt_off}},
        {DT_NULL, {0}}
    };
    size_t dynamic_off = b->size;
    memcpy(b->mem + dynamic_off, dynamic, sizeof(dynamic));
    b->size += sizeof(dynamic);

    // Añade secciones
    size_t idx_dynstr = elf_builder_add_section_ex(b, ".dynstr", SHT_STRTAB, SHF_ALLOC,
        b->mem + dynstr_off, dynstr_size, base_vaddr + dynstr_off, 1, NULL, NULL, 0, 0, 0);

    size_t idx_dynsym = elf_builder_add_section_ex(b, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
        b->mem + dynsym_off, sizeof(dynsym), base_vaddr + dynsym_off, 8, NULL, NULL,
        idx_dynstr, 1, sizeof(Elf64_Sym)); // sh_link = idx_dynstr, sh_info = 1 símbolo local
    size_t idx_gotplt = elf_builder_add_section(b, ".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, b->mem + got_plt_off, sizeof(got_plt), base_vaddr + got_plt_off, 8, NULL, NULL);

    size_t idx_relaplt = elf_builder_add_section_ex(b, ".rela.plt", SHT_RELA, SHF_ALLOC,
        b->mem + rela_plt_off, sizeof(rela), base_vaddr + rela_plt_off, 8, NULL, NULL,
        idx_dynsym, idx_gotplt, sizeof(Elf64_Rela)); // sh_link = idx_dynsym, sh_info = idx_gotplt

    size_t idx_dynamic = elf_builder_add_section_ex(b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
        b->mem + dynamic_off, sizeof(dynamic), base_vaddr + dynamic_off, 8, NULL, NULL,
        0, 0, sizeof(Elf64_Dyn));
    size_t shstrtab_off = b->size;
    memcpy(b->mem + shstrtab_off, b->shstrtab, b->shstrtab_len);
    b->size += b->shstrtab_len;
    size_t idx_shstrtab = elf_builder_add_section_ex(b, ".shstrtab", SHT_STRTAB, 0,
        b->mem + shstrtab_off, b->shstrtab_len, 0, 1, NULL, NULL, 0, 0, 0);

    // Parchea el call (offset relativo a RIP)
    // call printf está en offset 13, el destino es la PLT (pero usamos reloc)
    uint64_t rip_after = text_section_vaddr + 13 + 4 + 1;
    int32_t rel32 = 0; // El linker lo rellenará
    *(uint32_t *)(b->mem + text_section_off + 14) = rel32;

    // Finaliza el ELF ejecutable (corregido para dos segmentos)
    // 1. Segmento RX: .text
    // 2. Segmento RW: .data, .dynamic, .got.plt, etc.
    // Creamos manualmente los program headers para cubrir ambos rangos

    // --- Finaliza ELF ---
    // Calcula el rango de datos
    size_t phnum = 2;
    size_t phdr_size = phnum * sizeof(Elf64_Phdr);
    // Alinear el offset para la tabla de secciones
    if (b->size % 8 != 0) b->size = (b->size + 7) & ~7;
    size_t shdr_offset = b->size;
    // Copia la tabla de secciones al final del archivo
    memcpy(b->mem + shdr_offset, b->shdr, b->shnum * sizeof(Elf64_Shdr));
    b->size += b->shnum * sizeof(Elf64_Shdr);

    // ELF header
    Elf64_Header *ehdr = (Elf64_Header *)b->ehdr;
    memset(ehdr, 0, sizeof(*ehdr));
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr->e_ident[EI_ABIVERSION] = 0;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = text_section_vaddr;
    ehdr->e_phoff = sizeof(Elf64_Header);
    ehdr->e_shoff = shdr_offset;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(Elf64_Header);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = phnum;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_shnum = b->shnum;
    ehdr->e_shstrndx = b->shstrndx;

    // Program headers
    Elf64_Phdr *phdr = (Elf64_Phdr *)(b->mem + sizeof(Elf64_Header));
    // RX segment (.text)
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_offset = text_section_off;
    phdr[0].p_vaddr = text_section_vaddr;
    phdr[0].p_paddr = text_section_vaddr;
    phdr[0].p_filesz = code_size;
    phdr[0].p_memsz = code_size;
    phdr[0].p_flags = PF_X | PF_R;
    phdr[0].p_align = PAGE_SIZE;
    // RW segment (.data + dinámicas)
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_offset = data_section_off;
    phdr[1].p_vaddr = data_section_vaddr;
    phdr[1].p_paddr = data_section_vaddr;
    phdr[1].p_filesz = b->size - data_section_off;
    phdr[1].p_memsz = b->size - data_section_off;
    phdr[1].p_flags = PF_W | PF_R;
    phdr[1].p_align = PAGE_SIZE;

    FILE *f = fopen("salida_printf.elf", "wb");
    if (!f) { perror("Error al abrir el archivo de salida"); elf_builder_free(b); return 1; }
    fwrite(b->mem, 1, b->size, f);
    fclose(f);
    printf("ELF ejecutable generado: salida_printf.elf (%zu bytes)\n", b->size);
    printf("Para hacerlo ejecutable: chmod +x salida_printf.elf\n");
    printf("Si al ejecutar ves 'Hola mundo', funciono\n");
    elf_builder_free(b);
    return 0;
}
