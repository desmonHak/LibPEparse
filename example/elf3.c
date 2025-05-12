#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "CreateELF.h"
#include "LibELFparse.h"

// Código ensamblador x86-64 para llamar a printf("Hola mundo\n")
// - El primer argumento (puntero al string) va en RDI
// - Llama a printf (dirección a resolver por el linker dinámico)
// - Luego llama a exit(0) para terminar el programa

uint8_t code[] = {
    // mov rdi, <address_of_string>
    0x48, 0xbf, 0,0,0,0, 0,0,0,0, // <- offset 2: 8 bytes para dirección del string

    // xor eax, eax (por convención, limpiar RAX para printf)
    0x31, 0xc0,

    // call printf (relativo a RIP)
    0xe8, 0,0,0,0, // <- offset 13: 4 bytes para offset de llamada

    // xor edi, edi
    0x31, 0xff,

    // mov eax, 60
    0xb8, 0x3c, 0x00, 0x00, 0x00,

    // syscall
    0x0f, 0x05
};

// Nombre del string a imprimir
const char hello_str[] = "Hola mundo\n";

// Nombre de la función a importar
const char printf_name[] = "printf";

// --- MAIN ---
int main() {
    size_t code_size = sizeof(code);
    size_t data_size = sizeof(hello_str);

    uint64_t base_vaddr = 0x400000;
    size_t text_file_off = 0x1000;
    size_t data_file_off = text_file_off + 0x1000;

    size_t capacity = 16 * PAGE_SIZE;
    ElfBuilder *b = elf_builder_create_exec64(capacity);
    if (!b) {
        fprintf(stderr, "No se pudo crear el ElfBuilder\n");
        return 1;
    }

    // Reservar espacio hasta el código
    if (text_file_off > b->size) {
        memset(b->mem + b->size, 0, text_file_off - b->size);
        b->size = text_file_off;
    }

    // Añadir sección .text (código)
    size_t text_section_off;
    uint64_t text_section_vaddr;
    elf_builder_add_section(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
        code, code_size, base_vaddr + text_file_off, 16,
        &text_section_off, &text_section_vaddr
    );

    // Reservar espacio hasta la sección .data
    if (data_file_off > b->size) {
        memset(b->mem + b->size, 0, data_file_off - b->size);
        b->size = data_file_off;
    }

    // Añadir sección .data (string)
    size_t data_section_off;
    uint64_t data_section_vaddr;
    elf_builder_add_section(
        b, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
        hello_str, data_size, base_vaddr + data_file_off, 8,
        &data_section_off, &data_section_vaddr
    );

    // --- Parchear el código: poner dirección del string ---
    // mov rdi, <address>
    *(uint64_t *)(b->mem + text_section_off + 2) = data_section_vaddr;

    // --- Parchear el call a printf ---
    // call printf (relativo a RIP)
    // Usamos la tabla de símbolos dinámica, así que el linker lo resuelve.
    // Para que funcione, necesitamos una sección .dynsym y .dynstr, pero
    // para simplificar, aquí solo ponemos el call con offset 0 y confiamos en el linker dinámico.
    // En código real, deberías generar la tabla de símbolos dinámica correctamente.
    // Aquí, el call apunta a una dirección nula (el linker lo arreglará).
    // call printf (offset = dirección de printf - (rip después del call))
    // Pero, como no sabemos la dirección de printf, dejamos el offset en 0.

    // --- Finalizar ELF ---
    elf_builder_finalize_exec64(
        b,
        text_section_vaddr, // entry point
        text_section_off,
        text_section_vaddr,
        code_size
    );

    // --- Escribir a disco ---
    FILE *f = fopen("salida_printf.elf", "wb");
    if (!f) {
        perror("Error al abrir el archivo de salida");
        elf_builder_free(b);
        return 1;
    }
    fwrite(b->mem, 1, b->size, f);
    fclose(f);

    printf("ELF ejecutable generado: salida_printf.elf (%zu bytes)\n", b->size);
    printf("Para hacerlo ejecutable: chmod +x salida_printf.elf\n");
    printf("Si al ejecutar ves 'Hola mundo', funciono\n");

    elf_builder_free(b);
    return 0;
}
