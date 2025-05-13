//
// Created by desmon0xff on 13/05/2025.
//

#ifndef I386_H
#define I386_H

#ifndef ELF_RELOC
    #define ELF_RELOC(name, value)      \
    case name:                      \
    return #name;
#endif // ELF_RELOC


#define	R_386_NONE	0
#define	R_386_32	1
#define	R_386_PC32	2
#define	R_386_GOT32	3
#define	R_386_PLT32	4
#define	R_386_COPY	5
#define	R_386_GLOB_DAT	6
#define	R_386_JMP_SLOT	7
#define R_386_JUMP_SLOT R_386_JMP_SLOT
#define	R_386_RELATIVE	8
#define	R_386_GOTOFF	9
#define	R_386_GOTPC	10
#define	R_386_32PLT	11
/* TLS relocations */
#define	R_386_TLS_TPOFF	14
#define	R_386_TLS_IE	15
#define	R_386_TLS_GOTIE	16
#define	R_386_TLS_LE	17
#define	R_386_TLS_GD	18
#define	R_386_TLS_LDM	19
/* The following relocations are GNU extensions. */
#define	R_386_16	20
#define	R_386_PC16	21
#define	R_386_8		22
#define	R_386_PC8	23
/* More TLS relocations */
#define	R_386_TLS_GD_32		24
#define	R_386_TLS_GD_PUSH	25
#define	R_386_TLS_GD_CALL	26
#define	R_386_TLS_GD_POP	27
#define	R_386_TLS_LDM_32	28
#define	R_386_TLS_LDM_PUSH	29
#define	R_386_TLS_LDM_CALL	30
#define	R_386_TLS_LDM_POP	31
#define	R_386_TLS_LDO_32	32
#define	R_386_TLS_IE_32		33
#define	R_386_TLS_LE_32		34
#define	R_386_TLS_DTPMOD32	35
#define	R_386_TLS_DTPOFF32	36
#define	R_386_TLS_TPOFF32	37
#define R_386_SIZE32		38
/* More TLS relocations */
#define	R_386_TLS_GOTDESC	39
#define	R_386_TLS_DESC_CALL	40
#define	R_386_TLS_DESC		41
#define R_386_IRELATIVE		42
#define R_386_GOT32X		43

static inline const char *get_relocs_x86(uint32_t Type) {
    switch (Type) {
        ELF_RELOC(R_386_NONE,           0)
        ELF_RELOC(R_386_32,             1)
        ELF_RELOC(R_386_PC32,           2)
        ELF_RELOC(R_386_GOT32,          3)
        ELF_RELOC(R_386_PLT32,          4)
        ELF_RELOC(R_386_COPY,           5)
        ELF_RELOC(R_386_GLOB_DAT,       6)
        ELF_RELOC(R_386_JUMP_SLOT,      7)
        ELF_RELOC(R_386_RELATIVE,       8)
        ELF_RELOC(R_386_GOTOFF,         9)
        ELF_RELOC(R_386_GOTPC,          10)
        ELF_RELOC(R_386_32PLT,          11)
        ELF_RELOC(R_386_TLS_TPOFF,      14)
        ELF_RELOC(R_386_TLS_IE,         15)
        ELF_RELOC(R_386_TLS_GOTIE,      16)
        ELF_RELOC(R_386_TLS_LE,         17)
        ELF_RELOC(R_386_TLS_GD,         18)
        ELF_RELOC(R_386_TLS_LDM,        19)
        ELF_RELOC(R_386_16,             20)
        ELF_RELOC(R_386_PC16,           21)
        ELF_RELOC(R_386_8,              22)
        ELF_RELOC(R_386_PC8,            23)
        ELF_RELOC(R_386_TLS_GD_32,      24)
        ELF_RELOC(R_386_TLS_GD_PUSH,    25)
        ELF_RELOC(R_386_TLS_GD_CALL,    26)
        ELF_RELOC(R_386_TLS_GD_POP,     27)
        ELF_RELOC(R_386_TLS_LDM_32,     28)
        ELF_RELOC(R_386_TLS_LDM_PUSH,   29)
        ELF_RELOC(R_386_TLS_LDM_CALL,   30)
        ELF_RELOC(R_386_TLS_LDM_POP,    31)
        ELF_RELOC(R_386_TLS_LDO_32,     32)
        ELF_RELOC(R_386_TLS_IE_32,      33)
        ELF_RELOC(R_386_TLS_LE_32,      34)
        ELF_RELOC(R_386_TLS_DTPMOD32,   35)
        ELF_RELOC(R_386_TLS_DTPOFF32,   36)
        ELF_RELOC(R_386_TLS_TPOFF32,    37)
        ELF_RELOC(R_386_TLS_GOTDESC,    39)
        ELF_RELOC(R_386_TLS_DESC_CALL,  40)
        ELF_RELOC(R_386_TLS_DESC,       41)
        ELF_RELOC(R_386_IRELATIVE,      42)
        ELF_RELOC(R_386_GOT32X,         43)

        default: return NULL;
    }

}

#endif //I386_H
