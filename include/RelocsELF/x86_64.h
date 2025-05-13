//
// Created by desmon0xff on 13/05/2025.
//

#ifndef X86_64_H
#define X86_64_H

#define R_X86_64_NONE		0
#define R_X86_64_64		    1
#define R_X86_64_PC32		2
#define R_X86_64_GOT32		3
#define R_X86_64_PLT32		4
#define R_X86_64_COPY		5
#define R_X86_64_GLOB_DAT	6
#define R_X86_64_JUMP_SLOT	7
#define R_X86_64_RELATIVE	8
#define R_X86_64_GOTPCREL	9
#define R_X86_64_32		    10
#define R_X86_64_32S		11
#define R_X86_64_16		    12
#define R_X86_64_PC16		13
#define R_X86_64_8		    14
#define R_X86_64_PC8		15

#define R_X86_64_DTPMOD64	16
#define R_X86_64_DTPOFF64	17
#define R_X86_64_TPOFF64	18
#define R_X86_64_TLSGD		19
#define R_X86_64_TLSLD		20
#define R_X86_64_DTPOFF32	21
#define R_X86_64_GOTTPOFF	22
#define R_X86_64_TPOFF32	23
#define R_X86_64_PC64		24
#define R_X86_64_GOTOFF64	25
#define R_X86_64_GOTPC32	26
#define R_X86_64_GOT64		27
#define R_X86_64_GOTPCREL64	28
#define R_X86_64_GOTPC64	29
#define R_X86_64_GOTPLT64	30
#define R_X86_64_PLTOFF64	31
#define R_X86_64_SIZE32		32
#define R_X86_64_SIZE64		33
#define R_X86_64_GOTPC32_TLSDESC 34
#define R_X86_64_TLSDESC_CALL	35
#define R_X86_64_TLSDESC	    36
#define R_X86_64_IRELATIVE	    37
#define R_X86_64_RELATIVE64	    38
#define R_X86_64_PC32_BND	    39
#define R_X86_64_PLT32_BND	    40
#define R_X86_64_GOTPCRELX	    41
#define R_X86_64_REX_GOTPCRELX	42

#ifndef get_relocs
#define get_relocs(machine) get_relocs ## _ ## machine
#endif

#ifndef ELF_RELOC
    #define ELF_RELOC(name, value)      \
        case name:                      \
            return #name;

#endif // ELF_RELOC

#ifndef ELF_RELOC
#error "ELF_RELOC must be defined"
#endif // ELF_RELOC




static inline const char *get_relocs_x86_64(uint32_t Type) {
    switch (Type) {
        ELF_RELOC(R_X86_64_NONE,        0)
        ELF_RELOC(R_X86_64_64,          1)
        ELF_RELOC(R_X86_64_PC32,        2)
        ELF_RELOC(R_X86_64_GOT32,       3)
        ELF_RELOC(R_X86_64_PLT32,       4)
        ELF_RELOC(R_X86_64_COPY,        5)
        ELF_RELOC(R_X86_64_GLOB_DAT,    6)
        ELF_RELOC(R_X86_64_JUMP_SLOT,   7)
        ELF_RELOC(R_X86_64_RELATIVE,    8)
        ELF_RELOC(R_X86_64_GOTPCREL,    9)
        ELF_RELOC(R_X86_64_32,          10)
        ELF_RELOC(R_X86_64_32S,         11)
        ELF_RELOC(R_X86_64_16,          12)
        ELF_RELOC(R_X86_64_PC16,        13)
        ELF_RELOC(R_X86_64_8,           14)
        ELF_RELOC(R_X86_64_PC8,         15)
        ELF_RELOC(R_X86_64_DTPMOD64,    16)
        ELF_RELOC(R_X86_64_DTPOFF64,    17)
        ELF_RELOC(R_X86_64_TPOFF64,     18)
        ELF_RELOC(R_X86_64_TLSGD,       19)
        ELF_RELOC(R_X86_64_TLSLD,       20)
        ELF_RELOC(R_X86_64_DTPOFF32,    21)
        ELF_RELOC(R_X86_64_GOTTPOFF,    22)
        ELF_RELOC(R_X86_64_TPOFF32,     23)
        ELF_RELOC(R_X86_64_PC64,        24)
        ELF_RELOC(R_X86_64_GOTOFF64,    25)
        ELF_RELOC(R_X86_64_GOTPC32,     26)
        ELF_RELOC(R_X86_64_GOT64,       27)
        ELF_RELOC(R_X86_64_GOTPCREL64,  28)
        ELF_RELOC(R_X86_64_GOTPC64,     29)
        ELF_RELOC(R_X86_64_GOTPLT64,    30)
        ELF_RELOC(R_X86_64_PLTOFF64,    31)
        ELF_RELOC(R_X86_64_SIZE32,      32)
        ELF_RELOC(R_X86_64_SIZE64,      33)
        ELF_RELOC(R_X86_64_GOTPC32_TLSDESC,  34)
        ELF_RELOC(R_X86_64_TLSDESC_CALL,     35)
        ELF_RELOC(R_X86_64_TLSDESC,     36)
        ELF_RELOC(R_X86_64_IRELATIVE,   37)
        ELF_RELOC(R_X86_64_GOTPCRELX,   41)
        ELF_RELOC(R_X86_64_REX_GOTPCRELX,    42)
        default: return NULL;
    }
}



#endif //X86_64_H
