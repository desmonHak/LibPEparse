#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
int main() {
    puts("Esto solo es compilable en windows");
    return 0;
}

#else
#include <windows.h>

#include "LibPEparse.h"

#define IMAGE_BASE 0x400000
#define SECT_ALIGN 0x1000
#define FILE_ALIGN 0x200

// Structure definitions for PE elements
typedef struct {
    ___IMAGE_DOS_HEADER dosHeader;
    ___IMAGE_NT_HEADERS64 ntHeaders;
    ___IMAGE_SECTION_HEADER* sectionHeaders;
    _BYTE** sectionData;
    int numberOfSections;
} PE64FILE_struct;

// Prototipos de funciones
void initializePE64File(PE64FILE_struct* pe);
void addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, _BYTE* data, _DWORD dataSize);
void finalizePE64File(PE64FILE_struct* pe);
void writePE64File(PE64FILE_struct* pe, const char* filename);
void freePE64File(PE64FILE_struct* pe);


void initializePE64File(PE64FILE_struct* pe) {
    memset(pe, 0, sizeof(PE64FILE_struct));

    // DOS Header
    pe->dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
    pe->dosHeader.e_lfanew = sizeof(___IMAGE_DOS_HEADER);

    // NT Headers
    pe->ntHeaders.Signature = IMAGE_NT_SIGNATURE;
    pe->ntHeaders.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    pe->ntHeaders.FileHeader.NumberOfSections = 0;
    pe->ntHeaders.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    pe->ntHeaders.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    // Optional Header
    pe->ntHeaders.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pe->ntHeaders.OptionalHeader.MajorLinkerVersion = 14;
    pe->ntHeaders.OptionalHeader.MinorLinkerVersion = 0;
    pe->ntHeaders.OptionalHeader.ImageBase = IMAGE_BASE;
    pe->ntHeaders.OptionalHeader.SectionAlignment = SECT_ALIGN;
    pe->ntHeaders.OptionalHeader.FileAlignment = FILE_ALIGN;
    pe->ntHeaders.OptionalHeader.MajorOperatingSystemVersion = 6;
    pe->ntHeaders.OptionalHeader.MinorOperatingSystemVersion = 0;
    pe->ntHeaders.OptionalHeader.MajorImageVersion = 0;
    pe->ntHeaders.OptionalHeader.MinorImageVersion = 0;
    pe->ntHeaders.OptionalHeader.MajorSubsystemVersion = 6;
    pe->ntHeaders.OptionalHeader.MinorSubsystemVersion = 0;
    pe->ntHeaders.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    pe->ntHeaders.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    pe->ntHeaders.OptionalHeader.SizeOfStackReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfStackCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = 0x400; // Valor inicial mayor
}

void addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, _BYTE* data, _DWORD dataSize) {
    pe->numberOfSections++;
    pe->sectionHeaders = realloc(pe->sectionHeaders, pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER));
    pe->sectionData = realloc(pe->sectionData, pe->numberOfSections * sizeof(_BYTE*));

    ___IMAGE_SECTION_HEADER* newSection = &pe->sectionHeaders[pe->numberOfSections - 1];
    memset(newSection, 0, sizeof(___IMAGE_SECTION_HEADER));
    strncpy((char*)newSection->Name, name, IMAGE_SIZEOF_SHORT_NAME);

    newSection->Misc.VirtualSize = dataSize;
    
    // Calcular VirtualAddress
    if (pe->numberOfSections == 1) {
        newSection->VirtualAddress = SECT_ALIGN;
    } else {
        newSection->VirtualAddress = align(pe->sectionHeaders[pe->numberOfSections - 2].VirtualAddress +
                                           pe->sectionHeaders[pe->numberOfSections - 2].Misc.VirtualSize,
                                           pe->ntHeaders.OptionalHeader.SectionAlignment);
    }

    newSection->SizeOfRawData = align(dataSize, FILE_ALIGN);

    // Calcular PointerToRawData
    if (pe->numberOfSections == 1) {
        newSection->PointerToRawData = align(sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                                             (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)),
                                             pe->ntHeaders.OptionalHeader.FileAlignment);
    } else {
        newSection->PointerToRawData = align(pe->sectionHeaders[pe->numberOfSections - 2].PointerToRawData +
                                             pe->sectionHeaders[pe->numberOfSections - 2].SizeOfRawData,
                                             pe->ntHeaders.OptionalHeader.FileAlignment);
    }

    newSection->Characteristics = characteristics;

    pe->sectionData[pe->numberOfSections - 1] = malloc(newSection->SizeOfRawData);
    memset(pe->sectionData[pe->numberOfSections - 1], 0, newSection->SizeOfRawData);
    memcpy(pe->sectionData[pe->numberOfSections - 1], data, dataSize);

    pe->ntHeaders.FileHeader.NumberOfSections = pe->numberOfSections;
    pe->ntHeaders.OptionalHeader.SizeOfImage = align(newSection->VirtualAddress + newSection->Misc.VirtualSize,
                                                     pe->ntHeaders.OptionalHeader.SectionAlignment);
}

void finalizePE64File(PE64FILE_struct* pe) {
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = align(sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                                                 (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)), FILE_ALIGN);
    pe->ntHeaders.OptionalHeader.AddressOfEntryPoint = pe->sectionHeaders[0].VirtualAddress;
    pe->ntHeaders.OptionalHeader.BaseOfCode = pe->sectionHeaders[0].VirtualAddress;

    // Actualizar SizeOfCode y SizeOfInitializedData
    pe->ntHeaders.OptionalHeader.SizeOfCode = 0;
    pe->ntHeaders.OptionalHeader.SizeOfInitializedData = 0;
    for (int i = 0; i < pe->numberOfSections; i++) {
        if (pe->sectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE)
            pe->ntHeaders.OptionalHeader.SizeOfCode += pe->sectionHeaders[i].SizeOfRawData;
        if (pe->sectionHeaders[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            pe->ntHeaders.OptionalHeader.SizeOfInitializedData += pe->sectionHeaders[i].SizeOfRawData;
    }
}

void writePE64File(PE64FILE_struct* pe, const char* filename) {
    FILE* fileHandle = fopen(filename, "wb");
    if (!fileHandle) {
        printf("Error opening file for writing.\n");
        return;
    }

    fwrite(&pe->dosHeader, sizeof(___IMAGE_DOS_HEADER), 1, fileHandle);
    fwrite(&pe->ntHeaders, sizeof(___IMAGE_NT_HEADERS64), 1, fileHandle);
    fwrite(pe->sectionHeaders, sizeof(___IMAGE_SECTION_HEADER), pe->numberOfSections, fileHandle);

    // Rellenar los headers
    _DWORD headerPadding = pe->ntHeaders.OptionalHeader.SizeOfHeaders -
                          (sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                           (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)));

    _BYTE* padding = calloc(1, headerPadding);
    fwrite(padding, 1, headerPadding, fileHandle);
    free(padding);

    // Escribir datos de cada seccion
    for (int i = 0; i < pe->numberOfSections; i++) {
        fseek(fileHandle, pe->sectionHeaders[i].PointerToRawData, SEEK_SET);
        fwrite(pe->sectionData[i], 1, pe->sectionHeaders[i].SizeOfRawData, fileHandle);
    }

    fclose(fileHandle);
}

void freePE64File(PE64FILE_struct* pe) {
    if (pe->sectionHeaders)
        free(pe->sectionHeaders);
    if (pe->sectionData) {
        for (int i = 0; i < pe->numberOfSections; i++)
            free(pe->sectionData[i]);
        free(pe->sectionData);
    }
}

int main() {
    PE64FILE_struct pe;
    initializePE64File(&pe);
    
    /*
     * En este ejemplo se asume que la seccion .text se carga en RVA = SECT_ALIGN (0x1000) 
     y que la IAT se encuentra en la seccion .idata en:
     * 
     *  IAT = idataSectionRVA + importAddressTableRVA
     *  RIP después de la instruccion call = SECT_ALIGN + (offset_call + tamaño_call)
     *  disp32 = IAT - (SECT_ALIGN + offset_call + tamaño_call)
     * 
     * En este codigo el call empieza en offset 11 (0-indexado) y ocupa 6 bytes (por lo que el 
     * RIP al terminar es SECT_ALIGN + 17). Asi, el desplazamiento se calcula como:
     * 
     *  disp32 = (idataSectionRVA + importAddressTableRVA) - (SECT_ALIGN + 17)
    */

    // Seccion .text: contiene codigo que realiza un call indirecto a ExitProcess
    _BYTE textSectionData[] = {
        0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 40h
        0x48, 0xC7, 0xC1, 0x2A, 0x00, 0x00, 0x00,   // mov rcx, 42
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,         // call [RIP+disp32] (disp32 a corregir)
        0xEB, 0xFE                                // jmp $
    };
    // Agregar seccion .text
    addSection(&pe, ".text", IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
               textSectionData, sizeof(textSectionData));

    // Preparacion de la seccion .idata
    // Se asume que .idata será la segunda seccion
    _DWORD idataSectionRVA = SECT_ALIGN * 2;  // 0x2000
    _DWORD importLookupTableRVA = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;  // Reservar espacio para descriptor + terminador
    _DWORD importAddressTableRVA = importLookupTableRVA + sizeof(_QWORD) * 2;
    _DWORD hintNameTableRVA = importAddressTableRVA + sizeof(_QWORD) * 2;
    _DWORD dllNameRVA = hintNameTableRVA + sizeof(WORD) + strlen("ExitProcess") + 1;
    
    _BYTE idataSectionData[1024] = {0};
    _DWORD offset = 0;

    // Import Directory Table
    IMAGE_IMPORT_DESCRIPTOR importDescriptor = {0};
    // Los campos se establecen como RVA absolutos (RVA de la seccion + offset interno)
    importDescriptor.OriginalFirstThunk = idataSectionRVA + importLookupTableRVA;
    importDescriptor.TimeDateStamp = 0;
    importDescriptor.ForwarderChain = 0;
    importDescriptor.Name = idataSectionRVA + dllNameRVA;
    importDescriptor.FirstThunk = idataSectionRVA + importAddressTableRVA;
    memcpy(idataSectionData + offset, &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // Terminador nulo para la tabla de directorios
    offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // Import Lookup Table (ILT)
    _QWORD iltEntry = idataSectionRVA + hintNameTableRVA;
    memcpy(idataSectionData + offset, &iltEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD);
    // Terminador nulo para ILT
    _QWORD nullEntry = 0;
    memcpy(idataSectionData + offset, &nullEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD);

    // Import Address Table (IAT) - inicialmente igual a ILT
    memcpy(idataSectionData + offset, &iltEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD);
    // Terminador nulo para IAT
    memcpy(idataSectionData + offset, &nullEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD);

    // Hint/Name Table
    WORD hint = 0;
    memcpy(idataSectionData + offset, &hint, sizeof(WORD));
    offset += sizeof(WORD);
    strcpy((char*)idataSectionData + offset, "ExitProcess");
    offset += strlen("ExitProcess") + 1;

    // Nombre de la DLL
    strcpy((char*)idataSectionData + offset, "KERNEL32.dll");
    offset += strlen("KERNEL32.dll") + 1;

    // Actualizar directorios de importacion en el OptionalHeader
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataSectionRVA;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = idataSectionRVA + importAddressTableRVA;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = sizeof(_QWORD) * 2;    

    // Agregar la seccion .idata
    addSection(&pe, ".idata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            idataSectionData, offset);

    // Corregir el target del call en la seccion .text:
    // La instruccion call (FF 15) se encuentra a partir del offset 11;
    // los 4 bytes de desplazamiento están en offset 13.
    // RIP después de la instruccion call = SECT_ALIGN + 17.
    // IAT (donde se encuentra la direccion de ExitProcess) = idataSectionRVA + importAddressTableRVA.
    _DWORD textBase = SECT_ALIGN;                // 0x1000
    _DWORD callRIP = textBase + 17;                // RIP tras call (0x1000 + 17)
    _DWORD iatAddress = idataSectionRVA + importAddressTableRVA;  // Por ejemplo, 0x2000 + 56
    _DWORD callDisp = iatAddress - callRIP;         // disp32 = IAT - (base + 17)
    memcpy(pe.sectionData[0] + 13, &callDisp, sizeof(_DWORD));

    // Establecer AddressOfEntryPoint
    pe.ntHeaders.OptionalHeader.AddressOfEntryPoint = SECT_ALIGN;
    // Actualizar SizeOfImage en funcion de la última seccion
    pe.ntHeaders.OptionalHeader.SizeOfImage = align(pe.sectionHeaders[pe.numberOfSections - 1].VirtualAddress + 
        pe.sectionHeaders[pe.numberOfSections - 1].Misc.VirtualSize,
        pe.ntHeaders.OptionalHeader.SectionAlignment);

    finalizePE64File(&pe);
    writePE64File(&pe, "nuevo_pe_desde_cero.exe");
    freePE64File(&pe);

    PE64FILE *file = PE64FILE_Create("nuevo_pe_desde_cero.exe", fopen("nuevo_pe_desde_cero.exe", "rb"));
    PE64FILE_PrintInfo64(file);

    printf("PE file created successfully.\n");
    return 0;
}
#endif