//
// Created by desmon0xff on 13/05/2025.
//

#ifndef POWERPC_H
#define POWERPC_H

// https://android.googlesource.com/platform/art/+/8c01f5c/runtime/elf.h

// ELF Relocation types for PPC32
enum {
    R_PPC_NONE                  = 0,      /* No relocation. */
    R_PPC_ADDR32                = 1,
    R_PPC_ADDR24                = 2,
    R_PPC_ADDR16                = 3,
    R_PPC_ADDR16_LO             = 4,
    R_PPC_ADDR16_HI             = 5,
    R_PPC_ADDR16_HA             = 6,
    R_PPC_ADDR14                = 7,
    R_PPC_ADDR14_BRTAKEN        = 8,
    R_PPC_ADDR14_BRNTAKEN       = 9,
    R_PPC_REL24                 = 10,
    R_PPC_REL14                 = 11,
    R_PPC_REL14_BRTAKEN         = 12,
    R_PPC_REL14_BRNTAKEN        = 13,
    R_PPC_GOT16                 = 14,
    R_PPC_GOT16_LO              = 15,
    R_PPC_GOT16_HI              = 16,
    R_PPC_GOT16_HA              = 17,
    R_PPC_RELATIVE              = 22,
    R_PPC_REL32                 = 26,
    R_PPC_TLS                   = 67,
    R_PPC_DTPMOD32              = 68,
    R_PPC_TPREL16               = 69,
    R_PPC_TPREL16_LO            = 70,
    R_PPC_TPREL16_HI            = 71,
    R_PPC_TPREL16_HA            = 72,
    R_PPC_TPREL32               = 73,
    R_PPC_DTPREL16              = 74,
    R_PPC_DTPREL16_LO           = 75,
    R_PPC_DTPREL16_HI           = 76,
    R_PPC_DTPREL16_HA           = 77,
    R_PPC_DTPREL32              = 78,
    R_PPC_GOT_TLSGD16           = 79,
    R_PPC_GOT_TLSGD16_LO        = 80,
    R_PPC_GOT_TLSGD16_HI        = 81,
    R_PPC_GOT_TLSGD16_HA        = 82,
    R_PPC_GOT_TLSLD16           = 83,
    R_PPC_GOT_TLSLD16_LO        = 84,
    R_PPC_GOT_TLSLD16_HI        = 85,
    R_PPC_GOT_TLSLD16_HA        = 86,
    R_PPC_GOT_TPREL16           = 87,
    R_PPC_GOT_TPREL16_LO        = 88,
    R_PPC_GOT_TPREL16_HI        = 89,
    R_PPC_GOT_TPREL16_HA        = 90,
    R_PPC_GOT_DTPREL16          = 91,
    R_PPC_GOT_DTPREL16_LO       = 92,
    R_PPC_GOT_DTPREL16_HI       = 93,
    R_PPC_GOT_DTPREL16_HA       = 94,
    R_PPC_TLSGD                 = 95,
    R_PPC_TLSLD                 = 96,
    R_PPC_REL16                 = 249,
    R_PPC_REL16_LO              = 250,
    R_PPC_REL16_HI              = 251,
    R_PPC_REL16_HA              = 252
};

#endif //POWERPC_H
