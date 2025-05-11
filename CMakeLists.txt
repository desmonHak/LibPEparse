cmake_minimum_required(VERSION 3.31)
project(LibPEparse C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

# example/code1.c
add_executable(code1
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/LibCOFFparse.c
        src/LibPEparse.c
        src/LibELFparse.c
        example/code1.c)

# example/code2.c
add_executable(code2
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        example/code2.c)

# example/coff1.c
add_executable(coff1
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        example/coff1.c)

# example/coff2.c
add_executable(coff2
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        example/coff2.c)

# example/coff3.c
add_executable(coff3
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        example/coff3.c)

if (MSVC)
    # warning level 4
    add_compile_options(/W4)
else()
    # additional warnings
    add_compile_options(-Wall -Wextra -Wpedantic -ggdb)
endif()
# example/main.c
add_executable(main
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        example/main.c)