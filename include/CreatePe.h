#ifndef CREATE_PE_H
#define CREATE_PE_H
#include "LibPEparse.h"

#define IMAGE_BASE 0x400000
#define SECT_ALIGN 0x1000
#define FILE_ALIGN 0x200

// Estructura para el archivo PE (simplificada)
typedef struct {
    ___IMAGE_DOS_HEADER dosHeader;
    ___IMAGE_NT_HEADERS64 ntHeaders;
    ___IMAGE_SECTION_HEADER* sectionHeaders;
    _BYTE** sectionData;
    int numberOfSections;
} PE64FILE_struct;

// Estructura para representar una libreria y sus funciones a importar
typedef struct {
    const char* dllName;      // Ej: "KERNEL32.dll"
    const char** functions;   // Ej: { "ExitProcess", "WriteConsoleA" }
    int numFunctions;         // Número de funciones en el array
} ImportLibrary;

// Estructura para mapear offsets de funciones
typedef struct FunctionOffset {
    int offset_iat;
    uint32_t offset_code;
    const char* name;
} FunctionOffset;

typedef struct {
    const char* functionName;
    const char* dllName;
    int offset; // offset relativo al inicio de la IAT
} ImportOffsetEntry;


// Prototipos de funciones auxiliares y de extension
void initializePE64File(PE64FILE_struct* pe);
int addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, _BYTE* data, _DWORD dataSize);
int getSectionIndex(PE64FILE_struct* pe, const char* name);
void appendToSection(PE64FILE_struct* pe, const char* name, _BYTE* data, _DWORD dataSize);
void addBssSection(PE64FILE_struct* pe, const char* name, _DWORD size);
_BYTE* buildIdataSection(const char* funcName, const char* dllName, _DWORD idataRVA, _DWORD* outSize);
void finalizePE64File(PE64FILE_struct* pe);
void writePE64File(PE64FILE_struct* pe, const char* filename);
void freePE64File(PE64FILE_struct* pe);
_BYTE* buildMultiIdataSection(ImportLibrary* libs, int numLibs, _DWORD idataRVA, _DWORD* outSize);
_BYTE* buildMultiIdataSectionWithOffsets(
    ImportLibrary* libs, int numLibs, _DWORD idataRVA, _DWORD* outSize,
    ImportOffsetEntry** outOffsets, int* outNumOffsets);
void parchearDesplazamientosPorOffset(
    uint8_t* codigo, size_t tamanoCodigo,
    uint64_t baseVirtualSeccion, uint64_t direccionIAT,
    FunctionOffset* funcOffsets, int numFunciones);

#endif