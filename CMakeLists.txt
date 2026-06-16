cmake_minimum_required(VERSION 3.15)
project(LibPEparse C)

# =============================================================================
#  LibPEparse -- libreria generica en C puro para PARSEAR y EMITIR formatos de
#  objeto/ejecutable: PE/COFF (Windows) y ELF (Linux).
#
#  Disenada para reutilizarse en CUALQUIER proyecto C o C++ (no depende de
#  VestaVM ni de windows.h: los tipos ___IMAGE_* son propios).  Se consume de
#  dos formas:
#
#    1) Standalone:   cmake .. && make           (compila tambien los ejemplos)
#    2) Subdirectorio: add_subdirectory(LibPEparse)
#                      target_link_libraries(mi_target PRIVATE LibPEparse)
#       (los ejemplos quedan OFF por defecto para no contaminar el build padre)
# =============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Detecta si se compila standalone (proyecto raiz) o como subdirectorio.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_LIBPEPARSE_IS_TOPLEVEL ON)
else()
    set(_LIBPEPARSE_IS_TOPLEVEL OFF)
endif()

option(LIBPEPARSE_BUILD_EXAMPLES
       "Compilar los ejecutables de ejemplo (code1/coff/elf/main)"
       ${_LIBPEPARSE_IS_TOPLEVEL})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
#  Libreria estatica reutilizable
# -----------------------------------------------------------------------------
set(LIBPEPARSE_SOURCES
        src/LibPEparse.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/CreatePe.c
        src/CreateELF.c
        src/UtilsC.c
)

add_library(LibPEparse STATIC ${LIBPEPARSE_SOURCES})

# El directorio include/ se propaga a quien enlace la lib (PUBLIC) para que
# CreatePe.h / CreateELF.h / LibCOFFparse.h sean visibles sin rutas manuales.
target_include_directories(LibPEparse PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# Alias con namespace para consumo idiomatico (target_link_libraries Vesta::PEparse).
add_library(Vesta::PEparse ALIAS LibPEparse)

if(MSVC)
    target_compile_options(LibPEparse PRIVATE /W3)
else()
    target_compile_options(LibPEparse PRIVATE -Wall -Wextra)
endif()

# -----------------------------------------------------------------------------
#  Ejemplos (solo si LIBPEPARSE_BUILD_EXAMPLES=ON; OFF como subdirectorio)
#
#  OJO: el ejemplo se llama "main" -> si se construyera dentro de un proyecto
#  padre chocaria con otros targets; por eso van gated.
# -----------------------------------------------------------------------------
if(LIBPEPARSE_BUILD_EXAMPLES)
    foreach(_ex code1 code2 coff1 coff2 coff3 main elf1 elf2 elf3 elf4)
        add_executable(${_ex} example/${_ex}.c)
        target_link_libraries(${_ex} PRIVATE LibPEparse)
    endforeach()
endif()
