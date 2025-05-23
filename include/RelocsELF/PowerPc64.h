//
// Created by desmon0xff on 13/05/2025.
//

#ifndef POWERPC64_H
#define POWERPC64_H

// https://android.googlesource.com/platform/art/+/8c01f5c/runtime/elf.h

// ELF Relocation types for PPC64
enum {
    R_PPC64_NONE = 0,
    R_PPC64_ADDR32 = 1,
    R_PPC64_ADDR24 = 2,
    R_PPC64_ADDR16 = 3,
    R_PPC64_ADDR16_LO = 4,
    R_PPC64_ADDR16_HI = 5,
    R_PPC64_ADDR16_HA = 6,
    R_PPC64_ADDR14 = 7,
    R_PPC64_ADDR14_BRTAKEN = 8,
    R_PPC64_ADDR14_BRNTAKEN = 9,
    R_PPC64_REL24 = 10,
    R_PPC64_REL14 = 11,
    R_PPC64_REL14_BRTAKEN = 12,
    R_PPC64_REL14_BRNTAKEN = 13,
    R_PPC64_GOT16 = 14,
    R_PPC64_GOT16_LO = 15,
    R_PPC64_GOT16_HI = 16,
    R_PPC64_GOT16_HA = 17,
    R_PPC64_RELATIVE = 22,
    R_PPC64_REL32 = 26,
    R_PPC64_ADDR64 = 38,
    R_PPC64_ADDR16_HIGHER = 39,
    R_PPC64_ADDR16_HIGHERA = 40,
    R_PPC64_ADDR16_HIGHEST = 41,
    R_PPC64_ADDR16_HIGHESTA = 42,
    R_PPC64_REL64 = 44,
    R_PPC64_TOC16 = 47,
    R_PPC64_TOC16_LO = 48,
    R_PPC64_TOC16_HI = 49,
    R_PPC64_TOC16_HA = 50,
    R_PPC64_TOC = 51,
    R_PPC64_ADDR16_DS = 56,
    R_PPC64_ADDR16_LO_DS = 57,
    R_PPC64_GOT16_DS = 58,
    R_PPC64_GOT16_LO_DS = 59,
    R_PPC64_TOC16_DS = 63,
    R_PPC64_TOC16_LO_DS = 64,
    R_PPC64_TLS = 67,
    R_PPC64_DTPMOD64 = 68,
    R_PPC64_TPREL16 = 69,
    R_PPC64_TPREL16_LO = 70,
    R_PPC64_TPREL16_HI = 71,
    R_PPC64_TPREL16_HA = 72,
    R_PPC64_TPREL64 = 73,
    R_PPC64_DTPREL16 = 74,
    R_PPC64_DTPREL16_LO = 75,
    R_PPC64_DTPREL16_HI = 76,
    R_PPC64_DTPREL16_HA = 77,
    R_PPC64_DTPREL64 = 78,
    R_PPC64_GOT_TLSGD16 = 79,
    R_PPC64_GOT_TLSGD16_LO = 80,
    R_PPC64_GOT_TLSGD16_HI = 81,
    R_PPC64_GOT_TLSGD16_HA = 82,
    R_PPC64_GOT_TLSLD16 = 83,
    R_PPC64_GOT_TLSLD16_LO = 84,
    R_PPC64_GOT_TLSLD16_HI = 85,
    R_PPC64_GOT_TLSLD16_HA = 86,
    R_PPC64_GOT_TPREL16_DS = 87,
    R_PPC64_GOT_TPREL16_LO_DS = 88,
    R_PPC64_GOT_TPREL16_HI = 89,
    R_PPC64_GOT_TPREL16_HA = 90,
    R_PPC64_GOT_DTPREL16_DS = 91,
    R_PPC64_GOT_DTPREL16_LO_DS = 92,
    R_PPC64_GOT_DTPREL16_HI = 93,
    R_PPC64_GOT_DTPREL16_HA = 94,
    R_PPC64_TPREL16_DS = 95,
    R_PPC64_TPREL16_LO_DS = 96,
    R_PPC64_TPREL16_HIGHER = 97,
    R_PPC64_TPREL16_HIGHERA = 98,
    R_PPC64_TPREL16_HIGHEST = 99,
    R_PPC64_TPREL16_HIGHESTA = 100,
    R_PPC64_DTPREL16_DS = 101,
    R_PPC64_DTPREL16_LO_DS = 102,
    R_PPC64_DTPREL16_HIGHER = 103,
    R_PPC64_DTPREL16_HIGHERA = 104,
    R_PPC64_DTPREL16_HIGHEST = 105,
    R_PPC64_DTPREL16_HIGHESTA = 106,
    R_PPC64_TLSGD = 107,
    R_PPC64_TLSLD = 108,
    R_PPC64_REL16 = 249,
    R_PPC64_REL16_LO = 250,
    R_PPC64_REL16_HI = 251,
    R_PPC64_REL16_HA = 252
};




#endif //POWERPC64_H
