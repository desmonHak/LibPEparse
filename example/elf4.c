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

    // crear parte del ELF con 5 cabeceras de prgorama:
    ElfBuilder *b = elf_builder_create_exec64(capacity, 5);
    if (!b) {
        fprintf(stderr, "Error creating ELF builder\n");
        return 1;
    }

    // Obtener los headers del programa.
    Elf64_Phdr *phdr = (Elf64_Phdr *)b->phdr;
    // asegurarse de que la memoria esta limpia
    memset(phdr, 0, b->phnum * sizeof(Elf64_Phdr));

    // obtenemos el offset despues del header:
    // Comienza después del encabezado ELF y los encabezados del programa,
    // que están al principio (desplazamiento 0).
    size_t current_file_offset = b->size;

    // El encabezado ELF y los encabezados del programa ocupan la primera parte de la primera página.
    // Deberemos alinear la seccion .text, para eso, alineamos el desplazamiento actual,
    // hasta obtener el nuevo desplazamiento
    if (current_file_offset % PAGE_SIZE != 0) {
        size_t padding = PAGE_SIZE - (current_file_offset % PAGE_SIZE);
        memset(b->mem + current_file_offset, 0, padding);
        current_file_offset += padding;
        b->size = current_file_offset; // Update builder's size to reflect padding
    }


    size_t text_section_off;     // offset para la seccion .text
    uint64_t text_section_vaddr; // Direccion virtual de la seccion .text
    size_t idx_text = elf_builder_add_section_ex(
        b, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, // Type, Flags (Allocatable, Executable)
        code, code_size, base_vaddr + current_file_offset, 16, // Data, Size, Virtual Address, Alignment
        &text_section_off, &text_section_vaddr, 0, 0, 0 // Extended fields (link, info, entsize)
    );
    printf("Direccion virtual de la seccion text: 0x%x, offset: %x", text_section_vaddr, text_section_off);
    current_file_offset = b->size; // Update current_file_offset after adding .text


    // Sección .plt (Procedure Linkage Table)
    // Define PLT0 (entrada global) y PLT1 (entrada específica para printf)
    uint8_t plt_code[] = {
        // PLT0 (Offset 0 - Configuración del dynamic linker)
        0xff, 0x35, 0,0,0,0,    // push QWORD PTR [rip+GOT[1]]: Apila link_map (puntero a metadatos)
        /**
         * Propósito: Apila el puntero link_map (estructura interna del linker que contiene información del módulo)
         * Direccionamiento: rip+offset calcula la dirección de GOT (Global Offset Table)
         */

        0xff, 0x25, 0,0,0,0,    // jmp QWORD PTR [rip+GOT[2]]: Salta a _dl_runtime_resolve (resolución dinámica)
        /**
         * Función: Transfiere control a _dl_runtime_resolve, función del dynamic linker que resuelve direcciones
         * Datos usados: GOT almacena la dirección de esta función
         */

        0x0f, 0x1f, 0x40, 0x00, // nop padding para alineación de 16 bytes
        /**
         * Razón: Alinea PLT0 a 16 bytes (requisito de arquitectura x86-64 para optimización)
         */

        // PLT1 (printf@plt, Offset 16 - Lógica específica)
        0xff, 0x25, 0,0,0,0,    // jmp QWORD PTR [rip+GOT_printf_offset]: Salto inicial (sin resolver)
        /**
         * Comportamiento inicial: Al primer llamado, GOT para printf apunta DE VUELTA a la siguiente instrucción (0x00 en el código)
         * Post-resolución: El dynamic linker actualiza GOT con la dirección real de printf
         */

        0x68, 0x00,0x00,0x00,0x00, // pushq 0: Índice de printf en .rela.plt
        /**
         * Apila el número 0 en la pila, que representa el índice de printf en la tabla .rela.plt
         * (donde el linker guarda información sobre qué símbolo necesita resolver)
         */

        0xe9, 0,0,0,0            // jmp PLT0: Inicia resolución
        /**
         * Salta a la primera entrada de la PLT (PLT0), que contiene la lógica para invocar al
         * dynamic linker (_dl_runtime_resolve).
         * PLT0 es el punto central que llama al dynamic linker, pasando la información necesaria
         * (el índice de símbolo y el contexto) para que resuelva la dirección real de la función externa.
         */
    };




    /**
     * Parchea la instrucción push QWORD PTR [rip+X] en la PLT (PLT0), que apunta a GOT (GOT+8):
     *  - b->mem + plt_section_off + 0: Dirección de la instrucción en memoria.
     *  - plt_section_vaddr + 6:        Valor de RIP después de ejecutar la instrucción (la instrucción ocupa 6 bytes).
     *  - got_plt_section_vaddr + 8:    Dirección de la entrada de la GOT a la que debe apuntar.
     *  - El offset se calcula como:    (GOT+8) - (RIP después de la instrucción).
     *
     *  El resultado se escribe en el offset de la instrucción (bytes 2-5 de la instrucción).
     */
    PATCH_PLT_OFFSET(b->mem, plt_section_off + 0, plt_section_vaddr + 6, got_plt_section_vaddr + 8);

    /**
     * Parchea la instrucción jmp QWORD PTR [rip+Y] en la PLT (PLT0), que apunta a GOT (GOT+16).
     *  - b->mem + plt_section_off + 6: Dirección de la instrucción en memoria.
     *  - plt_section_vaddr + 12:       Valor de RIP después de ejecutar la instrucción (la instrucción ocupa 6 bytes).
     *  - got_plt_section_vaddr + 16:   Dirección de la entrada de la GOT a la que debe apuntar.
     *  - El offset se calcula como:    (GOT+16) - (RIP después de la instrucción).
     *
     * El resultado se escribe en el offset de la instrucción (bytes 2-5 de la instrucción).
     */
    PATCH_PLT_OFFSET(b->mem, plt_section_off + 6,  plt_section_vaddr + 12, got_plt_section_vaddr + 16);

    /**
     * Parchea la instrucción jmp QWORD PTR [rip+Z] en la PLT (PLT1, para printf), que apunta a GOT (GOT+16).
     *  - b->mem + plt_section_off + 16: Dirección de la instrucción en memoria.
     *  - plt_section_vaddr + 22:        Valor de RIP después de ejecutar la instrucción (la instrucción ocupa 6 bytes).
     *  - got_plt_section_vaddr + 16:    Dirección de la entrada de la GOT a la que debe apuntar.
     *  - El offset se calcula como:     (GOT+16) - (RIP después de la instrucción).
     *
     * El resultado se escribe en el offset de la instrucción (bytes 2-5 de la instrucción).
     */
    PATCH_PLT_OFFSET(b->mem, plt_section_off + 16, plt_section_vaddr + 22, got_plt_section_vaddr + 16);


    *(uint32_t *) (b->mem + plt_section_off + 23) = 0;

    /**
     * Push índice de relocalización
     * La instrucción jmp salta al inicio de la PLT (PLT0).
     * El valor se escribe en b->mem + plt_section_off + 28 porque ahí empieza el operando de 4 bytes de la
     * instrucción jmp (la instrucción empieza en plt_section_off + 27).
     */
    *(int32_t *)(b->mem + plt_section_off + 28) = -32;

    // GOT[0] apunta a PLT1
    *(uint64_t *)(b->mem + got_plt_section_off + 0) = plt_section_vaddr + 16;


    return 0;
}