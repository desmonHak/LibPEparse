cmake_minimum_required(VERSION 3.31)
project(LibPEparse C)

set(CMAKE_C_STANDARD 11)

# Permitir establecer modo Debug o Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Configuraciones específicas por tipo de compilación
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -Wall -DDEBUG_ENABLE -Wpedantic -D_ExceptionHandler")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -D_ExceptionHandler")

include_directories(include)

# example/code1.c
add_executable(code1
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/LibCOFFparse.c
        src/LibPEparse.c
        src/LibELFparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/code1.c
        include/RelocsELF/RelocsELF.h
        include/RelocsELF/M68k.h
        include/RelocsELF/x86_64.h
        include/RelocsELF/i386.h
        include/RelocsELF/Mips.h
        include/RelocsELF/AArch64.h
        include/RelocsELF/ARM.h
        include/RelocsELF/ARC.h
        include/RelocsELF/AVR.h
        include/RelocsELF/Hexagon.h
        include/RelocsELF/Lanai.h
        include/RelocsELF/PowerPC.h
        include/RelocsELF/PowerPc64.h
        include/RelocsELF/RISCV.h
        include/RelocsELF/SystemZ.h
        include/RelocsELF/Sparc.h
        include/RelocsELF/AMDGPU.h
        include/RelocsELF/BPF.h
        include/RelocsELF/MSP430.h
        include/RelocsELF/VE.h
        include/RelocsELF/CSKY.h
        include/RelocsELF/LoongArch.h
        include/RelocsELF/Xtensa.h)

# example/code2.c
add_executable(code2
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/code2.c)

# example/coff1.c
add_executable(coff1
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/coff1.c)

# example/coff2.c
add_executable(coff2
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/coff2.c)

# example/coff3.c
add_executable(coff3
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/coff3.c)

if (MSVC)
    # warning level 4
    add_compile_options(/W4)
else()
    # additional warnings
    add_compile_options(
            -Wall -Wextra -Wpedantic -g -O0
    )
endif()
# example/main.c
add_executable(main
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/main.c)

# example/elf1.c
add_executable(elf1
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/elf1.c)
add_executable(elf2
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/elf2.c)
add_executable(elf3
        include/CreatePe.h
        include/LibCOFFparse.h
        include/LibELFparse.h
        include/LibPEparse.h
        include/UtilsC.h
        include/CreateELF.h
        src/CreatePe.c
        src/LibCOFFparse.c
        src/LibELFparse.c
        src/LibPEparse.c
        src/UtilsC.c
        src/CreateELF.c
        example/elf3.c)
