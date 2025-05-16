#ifndef UTILS_C
#define UTILS_C

#include "UtilsC.h"
#include "LibELFparse.h"

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <share.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

/**
 * Funcion multiplataforma para reserva de memoria
 *
 * - En Windows, VirtualAlloc ignora los conceptos de "anonima" y "privada"
 *      porque siempre reserva memoria privada para el proceso.
 *
 * - En POSIX, MAP_ANONYMOUS | MAP_PRIVATE es la opcion tipica para memoria
 *      dinámica sin respaldo de archivo.
 *
 * - En Windows, esta funcion asigna memoria de forma reservada y comprometida.
 *
 * Requiere enlazar con kernel32.lib (implicitamente en compiladores como MSVC).
 *
 *
 * @param size tamaño de la reservar. Debe de ser un multiplo de pagina de la maquina y sistema de destino
 * @param prot proteccion de la memoria
 * @param flags flags de la memoria
 * @return puntero a la memoria reservada.
 */

void* reserve_memory(size_t size, int prot, int flags) {
#if defined(_WIN32)
    DWORD flProtect = 0;
    DWORD dwAllocationType = MEM_RESERVE | MEM_COMMIT;

    if (prot & PROT_READ) {
        if (prot & PROT_WRITE) {
            flProtect = PAGE_READWRITE;
        } else if (prot & PROT_EXEC) {
            flProtect = PAGE_EXECUTE_READ;
        } else {
            flProtect = PAGE_READONLY;
        }
    } else if (prot & PROT_EXEC) {
        if (prot & PROT_WRITE) {
            flProtect = PAGE_EXECUTE_READWRITE;
        } else {
            flProtect = PAGE_EXECUTE;
        }
    } else {
        flProtect = PAGE_NOACCESS;
    }

    (void)flags;

    return VirtualAlloc(NULL, size, dwAllocationType, flProtect);
#else
    void* ptr = mmap(NULL, size, prot, flags, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
#endif
}

/**
 * Permite liberar la memoria reservada con reserve_memory
 * @param addr direccion de la memoria a liberar
 * @param size tamaño de la memoria a liberar, este parametro no tiene efecto en windows.
 * @return se devuelve 0 si la liberacion es correcta, en caso contrario, se devuelve algo distinto.
 */
int free_reserved_memory(void* addr, size_t size) {
#if defined(_WIN32)
    UNUSED_ARG(size); // en windows no se usara este arg
    return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
#else
    return munmap(addr, size);
#endif
}
/**
 * @brief Mapea un segmento de un archivo o memoria anonima en el espacio de direcciones del proceso.
 *
 * Esta funcion es multiplataforma y usa `mmap` en sistemas POSIX y `MapViewOfFileEx` en Windows.
 * Si se proporciona una direccion deseada (`desired_addr`) y se especifica la bandera `MAP_FIXED`,
 * la funcion intentará realizar el mapeo exactamente en esa direccion.
 *
 * - En Windows, se emula `MAP_FIXED` rechazando el mapeo si no se puede obtener la direccion exacta.
 * - Si `fd == -1`, se intenta un mapeo anonimo (en POSIX: `MAP_ANONYMOUS`; en Windows: se usa el archivo
 *      de paginacion).
 *
 * @param desired_addr Direccion donde se desea mapear el segmento, o `NULL` para que el sistema la elija.
 * @param size Tamaño del mapeo en bytes.
 * @param prot Protecciones de la memoria (ej. `PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
 * @param flags Banderas de mapeo (ej. `MAP_PRIVATE`, `MAP_ANONYMOUS`, `MAP_FIXED`).
 * @param fd Descriptor de archivo a mapear. Si es -1, se asume un mapeo anonimo.
 * @param offset Desplazamiento dentro del archivo desde donde comenzar el mapeo.
 * @return Puntero a la memoria mapeada, o `NULL` si falla.
 */
void* map_segment(void* desired_addr, size_t size, int prot, int flags, int fd, uint64_t offset) {
#if defined(_WIN32)
    DWORD flProtect = 0;
    DWORD dwDesiredAccess = 0;

    if (prot & PROT_READ) {
        if (prot & PROT_WRITE) {
            flProtect = PAGE_READWRITE;
            dwDesiredAccess = FILE_MAP_WRITE;
        } else if (prot & PROT_EXEC) {
            flProtect = PAGE_EXECUTE_READ;
            dwDesiredAccess = FILE_MAP_READ | FILE_MAP_EXECUTE;
        } else {
            flProtect = PAGE_READONLY;
            dwDesiredAccess = FILE_MAP_READ;
        }
    } else if (prot & PROT_EXEC) {
        flProtect = PAGE_EXECUTE;
        dwDesiredAccess = FILE_MAP_EXECUTE;
    } else {
        flProtect = PAGE_NOACCESS;
    }

    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    if (fd != -1) {
        fileHandle = (HANDLE)_get_osfhandle(fd);
    }

    HANDLE hMap = CreateFileMappingA(
        fileHandle,
        NULL,
        flProtect,
        (DWORD)((offset + size) >> 32),
        (DWORD)((offset + size) & 0xFFFFFFFF),
        NULL
    );

    if (!hMap) return NULL;

    void* addr = MapViewOfFileEx(
        hMap,
        dwDesiredAccess,
        (DWORD)(offset >> 32),
        (DWORD)(offset & 0xFFFFFFFF),
        size,
        (flags & 0x10 /* MAP_FIXED */) ? desired_addr : NULL
    );

    CloseHandle(hMap);

    // Emulacion básica de MAP_FIXED: si se especifica desired_addr y la direccion mapeada es distinta, se falla.
    if ((flags & 0x10 /* MAP_FIXED */) && addr != desired_addr) {
        if (addr) UnmapViewOfFile(addr);
        return NULL;
    }

    return addr;
#else
    void* ptr = mmap(desired_addr, size, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
#endif
}
#endif