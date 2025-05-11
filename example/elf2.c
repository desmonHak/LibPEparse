#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "CreateELF.h"
#include "LibELFparse.h"

// Pequeño programa de ejemplo en assembly x86-64
// Este código es el mínimo ejecutable que hace exit(0)
// xor %edi, %edi       ; Establece el código de retorno a 0
// mov $60, %eax        ; Syscall número 60 (sys_exit)
// syscall              ; Realiza la llamada al sistema
uint8_t exit_program[] = {
    // mov rax, 0x0a646c726f77
    0x48, 0xb8, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00, 0x00,
    0x50,                           // push rax

    // mov rax, 0x202c6f6c6c6548
    0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x00,
    0x50,                           // push rax

    // mov rsi, rsp
    0x48, 0x89, 0xe6,

    // mov rdx, 13
    0xba, 0x0d, 0x00, 0x00, 0x00,

    // mov rdi, 1
    0xbf, 0x01, 0x00, 0x00, 0x00,

    // mov rax, 1
    0xb8, 0x01, 0x00, 0x00, 0x00,

    // syscall
    0x0f, 0x05,

    // xor edi, edi
    0x31, 0xff,

    // mov eax, 60
    0xb8, 0x3c, 0x00, 0x00, 0x00,

    // syscall
    0x0f, 0x05
};

int main() {
    size_t code_size = sizeof(exit_program);
    uint64_t code_vaddr = 0x400000;  // Dirección típica de inicio en x86-64
    size_t code_file_off = 0x1000;   // Offset típico para código en ELF

    // Crear un ElfBuilder con capacidad suficiente
    size_t capacity = 16 * PAGE_SIZE; // 64KB debería ser suficiente
    ElfBuilder *b = elf_builder_create_exec64(capacity);
    if (!b) {
        fprintf(stderr, "No se pudo crear el ElfBuilder\n");
        return 1;
    }

    // Rellenar con ceros hasta el offset donde empieza el código
    size_t current_size = b->size;
    if (code_file_off > current_size) {
        memset(b->mem + current_size, 0, code_file_off - current_size);
        b->size = code_file_off;
    }

    // Añadir la sección .text con el código
    size_t text_section_off;
    uint64_t text_section_vaddr;
    elf_builder_add_section(b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                            exit_program, code_size, code_vaddr, PAGE_SIZE,
                            &text_section_off, &text_section_vaddr);

    // Finalizar el ELF ejecutable
    elf_builder_finalize_exec64(b, text_section_vaddr, text_section_off, text_section_vaddr, code_size);

    // Escribir a disco
    FILE *f = fopen("salida_exec.elf", "wb");
    if (!f) {
        perror("Error al abrir el archivo de salida");
        elf_builder_free(b);
        return 1;
    }

    size_t written = fwrite(b->mem, 1, b->size, f);
    if (written != b->size) {
        perror("Error al escribir el archivo ELF");
        fclose(f);
        elf_builder_free(b);
        return 1;
    }

    fclose(f);
    printf("ELF ejecutable generado: salida_exec.elf (%zu bytes)\n", b->size);

    // Mostrar permisos de ejecución
    printf("Para hacer el archivo ejecutable: chmod +x salida_exec.elf\n");

    // Liberar recursos
    elf_builder_free(b);

    // Verificar el ELF generado
    f = fopen("salida_exec.elf", "rb");
    if (!f) {
        perror("No se pudo abrir el archivo generado para verificación");
        return 1;
    }

    // Leer el archivo para verificación
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *mem = malloc(fsize);
    if (!mem) {
        perror("No se pudo asignar memoria para verificación");
        fclose(f);
        return 1;
    }

    if (fread(mem, 1, fsize, f) != fsize) {
        perror("Error al leer el archivo para verificación");
        free(mem);
        fclose(f);
        return 1;
    }

    fclose(f);

    // Analizar y mostrar información del ELF
    ElfFile elf;
    if (!elf_mem_parse(&elf, mem, fsize)) {
        printf("El archivo generado no es un ELF válido\n");
        free(mem);
        return 1;
    }

    show_elf_info(&elf);
    free(mem);

    return 0;
}