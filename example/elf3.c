#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

#define PAGE_SIZE 0x1000

int main() {
    // --- Assembly code: calls printf through PLT ---
    uint8_t code[] = {
        0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string>
        0x31, 0xc0,                   // xor eax, eax
        0xe8, 0,0,0,0,                // call printf@plt (offset to be filled later)
        0x31, 0xff,                   // xor edi, edi
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (sys_exit)
        0x0f, 0x05                    // syscall
    };

    const char hello_str[] = "Hello world\n";  // Changed to English for simplicity
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";
    const char dynstr[] = "\0printf\0libc.so.6\0";  // Dynamic string table

    size_t code_size = sizeof(code);
    size_t data_size = sizeof(hello_str);
    uint64_t base_vaddr = 0x400000;
    size_t capacity = 16 * PAGE_SIZE;
    ElfBuilder *b = elf_builder_create_exec64(capacity);

    // Place ELF header and program headers
    size_t phdr_size = sizeof(Elf64_Ehdr) + 4 * sizeof(Elf64_Phdr); // 4 phdrs
    if (phdr_size > b->size) {
        memset(b->mem + b->size, 0, phdr_size - b->size);
        b->size = phdr_size;
    }

    // Align sections to page boundary for better memory mapping
    size_t text_file_off = 0x1000;
    if (text_file_off > b->size) {
        memset(b->mem + b->size, 0, text_file_off - b->size);
        b->size = text_file_off;
    }

    // Add .text section
    size_t text_section_off;
    uint64_t text_section_vaddr;
    elf_builder_add_section_ex(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        code, code_size, base_vaddr + text_file_off, 16,
        &text_section_off, &text_section_vaddr, 0, 0, 0
    );

    // Add .plt section (PLT0 + PLT1)
    uint8_t plt_code[] = {
        // PLT0
        0xff, 0x35, 0,0,0,0,             // push QWORD PTR [rip+X] (got+8)
        0xff, 0x25, 0,0,0,0,             // jmp  QWORD PTR [rip+Y] (got+16)
        0x0f, 0x1f, 0x40, 0x00,          // nop dword ptr [rax+0x0]
        // PLT1 (printf)
        0xff, 0x25, 0,0,0,0,             // jmp QWORD PTR [rip+Z] (got+24)
        0x68, 0x00,0x00,0x00,0x00,       // pushq <reloc index>
        0xe9, 0,0,0,0                    // jmp .plt[0]
    };

    size_t plt_off = b->size;
    size_t plt_vaddr = base_vaddr + plt_off;
    elf_builder_add_section_ex(
        b, ".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        plt_code, sizeof(plt_code), plt_vaddr, 16, NULL, NULL, 0, 0, 0
    );

    // Ensure RW sections start at a new page boundary
    size_t rwdata_start = (b->size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (rwdata_start > b->size) {
        memset(b->mem + b->size, 0, rwdata_start - b->size);
        b->size = rwdata_start;
    }

    // Add .data section (contains our hello string)
    size_t data_section_off;
    uint64_t data_section_vaddr;
    elf_builder_add_section_ex(
        b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
        hello_str, data_size, base_vaddr + b->size, 8,
        &data_section_off, &data_section_vaddr, 0, 0, 0
    );

    // Patch the string address in the code
    *(uint64_t *)(b->mem + text_section_off + 2) = data_section_vaddr;

    // Add .dynstr section (dynamic string table)
    size_t dynstr_off = b->size;
    size_t dynstr_size = sizeof(dynstr);
    memcpy(b->mem + dynstr_off, dynstr, dynstr_size);
    b->size += dynstr_size;
    size_t idx_dynstr = elf_builder_add_section_ex(
        b, ".dynstr", SHT_STRTAB, SHF_ALLOC,
        b->mem + dynstr_off, dynstr_size,
        base_vaddr + dynstr_off, 1, NULL, NULL, 0, 0, 0
    );

    // Add .interp section (tells kernel which dynamic linker to use)
    size_t interp_off = b->size;
    memcpy(b->mem + interp_off, interp, sizeof(interp));
    b->size += sizeof(interp);
    size_t idx_interp = elf_builder_add_section_ex(
        b, ".interp", SHT_PROGBITS, SHF_ALLOC,
        b->mem + interp_off, sizeof(interp),
        base_vaddr + interp_off, 1, NULL, NULL, 0, 0, 0
    );

    // Add .dynsym section (dynamic symbol table)
    Elf64_Sym dynsym[2] = {0};
    // First entry is null symbol
    dynsym[0].st_name = 0;
    dynsym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    dynsym[0].st_shndx = SHN_UNDEF;
    // Second entry is printf symbol
    dynsym[1].st_name = 1; // offset in dynstr: "printf"
    dynsym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    dynsym[1].st_shndx = SHN_UNDEF;

    size_t dynsym_off = b->size;
    memcpy(b->mem + dynsym_off, dynsym, sizeof(dynsym));
    b->size += sizeof(dynsym);
    size_t idx_dynsym = elf_builder_add_section_ex(
        b, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
        b->mem + dynsym_off, sizeof(dynsym),
        base_vaddr + dynsym_off, 8, NULL, NULL, idx_dynstr, 1, sizeof(Elf64_Sym)
    );

    // Properly align .got.plt
    if (b->size % 8 != 0) {
        size_t padding = 8 - (b->size % 8);
        memset(b->mem + b->size, 0, padding);
        b->size += padding;
    }

    // Add .got.plt section (Global Offset Table for PLT)
    uint64_t got_plt[3] = {0}; // We need at least 3 entries
    size_t got_plt_off = b->size;
    uint64_t got_plt_vaddr = base_vaddr + got_plt_off;
    got_plt[0] = plt_vaddr; // First entry points to PLT0

    memcpy(b->mem + got_plt_off, got_plt, sizeof(got_plt));
    b->size += sizeof(got_plt);
    size_t idx_gotplt = elf_builder_add_section_ex(
        b, ".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
        b->mem + got_plt_off, sizeof(got_plt),
        got_plt_vaddr, 8, NULL, NULL, 0, 0, 0
    );

    // Add .rela.plt section (relocation entries for PLT)
    Elf64_Rela rela = {0};
    rela.r_offset = got_plt_vaddr + 2 * 8; // Third GOT entry (printf)
    rela.r_info = ELF64_R_INFO(1, R_X86_64_JUMP_SLOT); // Symbol 1 (printf)
    rela.r_addend = 0;

    size_t rela_plt_off = b->size;
    memcpy(b->mem + rela_plt_off, &rela, sizeof(rela));
    b->size += sizeof(rela);
    size_t idx_relaplt = elf_builder_add_section_ex(
        b, ".rela.plt", SHT_RELA, SHF_ALLOC,
        b->mem + rela_plt_off, sizeof(rela),
        base_vaddr + rela_plt_off, 8, NULL, NULL, idx_dynsym, idx_gotplt, sizeof(Elf64_Rela)
    );

    // Align .dynamic properly
    if (b->size % 16 != 0) {
        size_t padding = 16 - (b->size % 16);
        memset(b->mem + b->size, 0, padding);
        b->size += padding;
    }

    // Add .dynamic section (dynamic linking information)
    Elf64_Dyn dynamic[] = {
        {DT_NEEDED, {8}},                      // "libc.so.6"
        {DT_PLTGOT, {got_plt_vaddr}},          // .got.plt address
        {DT_STRTAB, {base_vaddr + dynstr_off}},
        {DT_SYMTAB, {base_vaddr + dynsym_off}},
        {DT_STRSZ, {dynstr_size}},
        {DT_SYMENT, {sizeof(Elf64_Sym)}},
        {DT_PLTRELSZ, {sizeof(rela)}},
        {DT_PLTREL, {DT_RELA}},
        {DT_JMPREL, {base_vaddr + rela_plt_off}},
        {DT_RELA, {base_vaddr + rela_plt_off}},
        {DT_RELASZ, {sizeof(rela)}},
        {DT_RELAENT, {sizeof(Elf64_Rela)}},
        {DT_NULL, {0}}
    };

    size_t dynamic_off = b->size;
    uint64_t dynamic_vaddr = base_vaddr + dynamic_off;
    memcpy(b->mem + dynamic_off, dynamic, sizeof(dynamic));
    b->size += sizeof(dynamic);
    size_t idx_dynamic = elf_builder_add_section_ex(
        b, ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
        b->mem + dynamic_off, sizeof(dynamic), dynamic_vaddr, 8,
        NULL, NULL, idx_dynstr, 0, sizeof(Elf64_Dyn)
    );

    // Patch GOT[1] with dynamic section address
    ((uint64_t *)(b->mem + got_plt_off))[1] = dynamic_vaddr;

    // Add .strtab section (string table for .symtab)
    const char strtab[] = "\0_start\0";
    size_t strtab_off = b->size;
    memcpy(b->mem + strtab_off, strtab, sizeof(strtab));
    b->size += sizeof(strtab);
    size_t idx_strtab = elf_builder_add_section_ex(
        b, ".strtab", SHT_STRTAB, 0,
        b->mem + strtab_off, sizeof(strtab),
        0, 1, NULL, NULL, 0, 0, 0
    );

    // Add .symtab section (symbol table with _start entry)
    Elf64_Sym symtab[2] = {0};
    symtab[0].st_name = 0; // null symbol
    symtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    symtab[0].st_shndx = SHN_UNDEF;

    symtab[1].st_name = 1; // "_start" in strtab
    symtab[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symtab[1].st_shndx = 1; // Section 1 (.text)
    symtab[1].st_value = text_section_vaddr;
    symtab[1].st_size = code_size;

    size_t symtab_off = b->size;
    memcpy(b->mem + symtab_off, symtab, sizeof(symtab));
    b->size += sizeof(symtab);
    size_t idx_symtab = elf_builder_add_section_ex(
        b, ".symtab", SHT_SYMTAB, 0,
        b->mem + symtab_off, sizeof(symtab),
        0, 8, NULL, NULL, idx_strtab, 1, sizeof(Elf64_Sym)
    );

    // Add .shstrtab section (section header string table)
    // Fix: Make sure to properly allocate and populate this section
    size_t shstrtab_off = b->size;
    memcpy(b->mem + shstrtab_off, b->shstrtab, b->shstrtab_len);
    b->size += b->shstrtab_len;
    size_t idx_shstrtab = elf_builder_add_section_ex(
        b, ".shstrtab", SHT_STRTAB, 0,
        b->mem + shstrtab_off, b->shstrtab_len,
        0, 1, NULL, NULL, 0, 0, 0
    );
    b->shstrndx = idx_shstrtab;

    // Patch the call to printf@plt in the code
    uint64_t call_addr = text_section_vaddr + 14;  // Address of call instruction + 4
    uint64_t plt1_addr = plt_vaddr + 16;           // Address of PLT1 (printf)
    int32_t rel32 = (int32_t)(plt1_addr - (call_addr + 4));
    *(int32_t *)(b->mem + text_section_off + 14) = rel32;

    // Patch offsets in PLT
    // PLT0: push [rip+X] where X points to GOT+8
    *(int32_t *)(b->mem + plt_off + 2) = (int32_t)(gotplt_addr + 8 - (plt_vaddr + 6));
    // PLT0: jmp [rip+Y] where Y points to GOT+16
    *(int32_t *)(b->mem + plt_off + 8) = (int32_t)(gotplt_addr + 16 - (plt_vaddr + 12));
    // PLT1: jmp [rip+Z] where Z points to GOT+24 (printf slot)
    *(int32_t *)(b->mem + plt_off + 18) = (int32_t)(gotplt_addr + 16 - (plt_vaddr + 22));
    // PLT1: pushq 0 (relocation index)
    *(int32_t *)(b->mem + plt_off + 24) = 0;
    // PLT1: jmp PLT0
    *(int32_t *)(b->mem + plt_off + 29) = (int32_t)(plt_vaddr - (plt_vaddr + 33));

    // Align section headers
    if (b->size % 8 != 0) {
        size_t padding = 8 - (b->size % 8);
        memset(b->mem + b->size, 0, padding);
        b->size += padding;
    }

    // Copy section headers to the end of the file
    size_t shdr_offset = b->size;
    memcpy(b->mem + shdr_offset, b->shdr, b->shnum * sizeof(Elf64_Shdr));
    b->size += b->shnum * sizeof(Elf64_Shdr);

    // Setup ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)b->mem;
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
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_shoff = shdr_offset;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 4;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_shnum = b->shnum;
    ehdr->e_shstrndx = b->shstrndx;

    // Setup program headers
    Elf64_Phdr *phdr = (Elf64_Phdr *)(b->mem + sizeof(Elf64_Ehdr));

    // RX segment (LOAD): Read-Execute, contains .text and .plt
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_offset = text_file_off;
    phdr[0].p_vaddr = text_section_vaddr;
    phdr[0].p_paddr = text_section_vaddr;
    phdr[0].p_filesz = rwdata_start - text_file_off;
    phdr[0].p_memsz = rwdata_start - text_file_off;
    phdr[0].p_flags = PF_X | PF_R;
    phdr[0].p_align = PAGE_SIZE;

    // RW segment (LOAD): Read-Write, contains .data, .got.plt, .dynamic, etc.
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_offset = rwdata_start;
    phdr[1].p_vaddr = base_vaddr + rwdata_start;
    phdr[1].p_paddr = base_vaddr + rwdata_start;
    phdr[1].p_filesz = shdr_offset - rwdata_start;
    phdr[1].p_memsz = shdr_offset - rwdata_start;
    phdr[1].p_flags = PF_W | PF_R;
    phdr[1].p_align = PAGE_SIZE;

    // INTERP segment: Points to dynamic linker path
    phdr[2].p_type = PT_INTERP;
    phdr[2].p_offset = interp_off;
    phdr[2].p_vaddr = base_vaddr + interp_off;
    phdr[2].p_paddr = base_vaddr + interp_off;
    phdr[2].p_filesz = sizeof(interp);
    phdr[2].p_memsz = sizeof(interp);
    phdr[2].p_flags = PF_R;
    phdr[2].p_align = 1;

    // DYNAMIC segment: Points to dynamic linking information
    phdr[3].p_type = PT_DYNAMIC;
    phdr[3].p_offset = dynamic_off;
    phdr[3].p_vaddr = dynamic_vaddr;
    phdr[3].p_paddr = dynamic_vaddr;
    phdr[3].p_filesz = sizeof(dynamic);
    phdr[3].p_memsz = sizeof(dynamic);
    phdr[3].p_flags = PF_R | PF_W;
    phdr[3].p_align = 8;

    // Write the ELF file
    FILE *f = fopen("fixed_hello.elf", "wb");
    if (!f) {
        perror("Error opening output file");
        elf_builder_free(b);
        return 1;
    }

    fwrite(b->mem, 1, b->size, f);
    fclose(f);

    printf("ELF executable generated: fixed_hello.elf (%zu bytes)\n", b->size);
    printf("To make it executable: chmod +x fixed_hello.elf\n");
    printf("If you see 'Hello world' when running it, it worked!\n");

    elf_builder_free(b);
    return 0;
}