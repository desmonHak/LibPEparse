#ifndef UTILSC_H
#define UTILSC_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
    #include <windows.h>
    #include <sys/stat.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

void* reserve_memory(size_t size, int prot, int flags);
int free_reserved_memory(void* addr, size_t size);
void* map_segment(void* desired_addr, size_t size, int prot, int flags, int fd, off_t offset);

#define MAP_PRIVATE_   0x02  // Cambios no se propagan al archivo original
#define MAP_ANONYMOUS_ 0x20  // No se mapea desde un archivo, sino memoria anónima
#define MAP_FIXED_     0x10  // Mapea exactamente en la dirección dada (opcional en la función)

#define PAGE_SIZE 4096  // Tamaño típico de una página de memoria

#endif //UTILSC_H
