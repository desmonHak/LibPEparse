#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

#define PAGE_SIZE 0x1000

int main() {

    uint8_t code[] = {
        0x48, 0xbf, 0,0,0,0, 0,0,0,0, // mov rdi, <address_of_string> (10 bytes)
        0x31, 0xc0,                   // xor eax, eax (2 bytes, for printf's %eax = 0)
        0xe8, 0,0,0,0,                // call printf@plt (5 bytes)
        0x31, 0xff,                   // xor edi, edi (2 bytes, for sys_exit's %edi = 0 status)
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (sys_exit) (5 bytes)
        0x0f, 0x05                    // syscall (2 bytes)
    };

    size_t code_size = sizeof(code);

    const char* linux_x86_64[] = {
        "printf"
    };

    // const char dynstr[] = "\0printf\0libc.so.6\0";
    ImportLibrary libs[] = {
        { "libc.so.6", linux_x86_64, sizeof(linux_x86_64) / sizeof(linux_x86_64[0]) }
    };
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";

    uint64_t base_vaddr = 0x400000;     // direccion base donde se carga el ejecutable
    size_t capacity = 16 * PAGE_SIZE;   // capacidad maxima para el ejecutable

    // crear parte del ELF con 4 cabeceras de prgorama:
    ElfBuilder *b = elf_builder_create_exec64(capacity, 4);
    if (!b) {
        fprintf(stderr, "Error creating ELF builder\n");
        return 1;
    }

    return 0;
}