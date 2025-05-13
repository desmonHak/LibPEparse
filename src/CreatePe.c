#include "CreatePe.h"

#include <string.h>

// Inicializa la estructura PE con headers minimos
void initializePE64File(PE64FILE_struct* pe) {
    memset(pe, 0, sizeof(PE64FILE_struct));
    // DOS Header
    pe->dosHeader.e_magic = ___IMAGE_DOS_SIGNATURE;
    pe->dosHeader.e_lfanew = sizeof(___IMAGE_DOS_HEADER);
    // NT Headers
    pe->ntHeaders.Signature = ___IMAGE_NT_SIGNATURE;
    pe->ntHeaders.FileHeader.Machine = ___IMAGE_FILE_MACHINE_AMD64;
    pe->ntHeaders.FileHeader.NumberOfSections = 0;
    pe->ntHeaders.FileHeader.SizeOfOptionalHeader = sizeof(___IMAGE_OPTIONAL_HEADER64);
    pe->ntHeaders.FileHeader.Characteristics = ___IMAGE_FILE_EXECUTABLE_IMAGE | 
                                            ___IMAGE_FILE_LARGE_ADDRESS_AWARE;
    // Optional Header
    pe->ntHeaders.OptionalHeader.Magic = ___IMAGE_NT_OPTIONAL_HDR64_MAGIC;
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
    pe->ntHeaders.OptionalHeader.Subsystem = ___IMAGE_SUBSYSTEM_WINDOWS_CUI;
    pe->ntHeaders.OptionalHeader.DllCharacteristics = ___IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                      ___IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                                      ___IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    pe->ntHeaders.OptionalHeader.SizeOfStackReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfStackCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.NumberOfRvaAndSizes = ___IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = 0x400; // Valor inicial mayor
}

// Agrega una nueva seccion al PE y retorna su indice
int addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, _BYTE* data, _DWORD dataSize) {
    pe->numberOfSections++;
    pe->sectionHeaders = realloc(pe->sectionHeaders, pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER));
    pe->sectionData = realloc(pe->sectionData, pe->numberOfSections * sizeof(_BYTE*));

    ___IMAGE_SECTION_HEADER* newSection = &pe->sectionHeaders[pe->numberOfSections - 1];
    memset(newSection, 0, sizeof(___IMAGE_SECTION_HEADER));
    strncpy((char*)newSection->Name, name, ___IMAGE_SIZEOF_SHORT_NAME);

    newSection->Misc.VirtualSize = dataSize;
    // Calcular VirtualAddress
    if (pe->numberOfSections == 1)
        newSection->VirtualAddress = SECT_ALIGN;
    else
        newSection->VirtualAddress = align(pe->sectionHeaders[pe->numberOfSections - 2].VirtualAddress +
                                             pe->sectionHeaders[pe->numberOfSections - 2].Misc.VirtualSize,
                                             pe->ntHeaders.OptionalHeader.SectionAlignment);

    newSection->SizeOfRawData = align(dataSize, FILE_ALIGN);
    // Calcular PointerToRawData
    if (pe->numberOfSections == 1)
        newSection->PointerToRawData = align(sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                                              (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)),
                                              pe->ntHeaders.OptionalHeader.FileAlignment);
    else
        newSection->PointerToRawData = align(pe->sectionHeaders[pe->numberOfSections - 2].PointerToRawData +
                                              pe->sectionHeaders[pe->numberOfSections - 2].SizeOfRawData,
                                              pe->ntHeaders.OptionalHeader.FileAlignment);

    newSection->Characteristics = characteristics;
    pe->sectionData[pe->numberOfSections - 1] = malloc(newSection->SizeOfRawData);
    memset(pe->sectionData[pe->numberOfSections - 1], 0, newSection->SizeOfRawData);
    if(data && dataSize > 0)
        memcpy(pe->sectionData[pe->numberOfSections - 1], data, dataSize);

    pe->ntHeaders.FileHeader.NumberOfSections = pe->numberOfSections;
    pe->ntHeaders.OptionalHeader.SizeOfImage = align(newSection->VirtualAddress + newSection->Misc.VirtualSize,
                                                      pe->ntHeaders.OptionalHeader.SectionAlignment);
    return pe->numberOfSections - 1;
}

// Retorna el indice de una seccion buscada por su nombre (o -1 si no se encuentra)
int getSectionIndex(PE64FILE_struct* pe, const char* name) {
    for (int i = 0; i < pe->numberOfSections; i++) {
        if (strncmp((char*)pe->sectionHeaders[i].Name, name, ___IMAGE_SIZEOF_SHORT_NAME) == 0)
            return i;
    }
    return -1;
}

// Anexa nuevos datos a una seccion existente (por ejemplo, para agregar codigo a .text)
void appendToSection(PE64FILE_struct* pe, const char* name, _BYTE* data, _DWORD dataSize) {
    int index = getSectionIndex(pe, name);
    if (index < 0) return;
    _DWORD currentSize = pe->sectionHeaders[index].Misc.VirtualSize;
    _DWORD newSize = currentSize + dataSize;
    _BYTE* newBuffer = realloc(pe->sectionData[index], align(newSize, FILE_ALIGN));
    if (!newBuffer) return;
    memcpy(newBuffer + currentSize, data, dataSize);
    pe->sectionData[index] = newBuffer;
    pe->sectionHeaders[index].Misc.VirtualSize = newSize;
    pe->sectionHeaders[index].SizeOfRawData = align(newSize, FILE_ALIGN);
}

// Agrega una seccion .bss (datos no inicializados) generando un buffer de ceros
void addBssSection(PE64FILE_struct* pe, const char* name, _DWORD size) {
    _BYTE* zeroBuffer = calloc(1, size);
    addSection(
        pe, name, ___IMAGE_SCN_CNT_UNINITIALIZED_DATA 
        | ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE, zeroBuffer, size);
    free(zeroBuffer);
}

// Construye una seccion .idata con múltiples entradas de importacion
// Parámetros:
//   libs: array de ImportLibrary
//   numLibs: cantidad de librerias
//   idataRVA: RVA base en la seccion .idata donde se ubicará el contenido
//   outSize: tamaño total del buffer generado (salida)
_BYTE* buildMultiIdataSection(ImportLibrary* libs, int numLibs, _DWORD idataRVA, _DWORD* outSize) {
    // 1. Tamaño de la Import Directory Table (una descriptor por libreria + uno nulo)
    _DWORD sizeImportDir = (numLibs + 1) * sizeof(___IMAGE_IMPORT_DESCRIPTOR);
    
    // 2. Para cada libreria se reservará ILT e IAT:
    _DWORD sizeILT_IAT = 0;
    for (int i = 0; i < numLibs; i++) {
        sizeILT_IAT += (libs[i].numFunctions + 1) * sizeof(_QWORD) * 2; // ILT + IAT
    }
    
    // 3. Para cada funcion, se necesita espacio para Hint/Name (WORD + cadena + terminador)
    _DWORD sizeHintName = 0;
    for (int i = 0; i < numLibs; i++) {
        for (int j = 0; j < libs[i].numFunctions; j++) {
            sizeHintName += sizeof(_WORD) + (_DWORD)strlen(libs[i].functions[j]) + 1;
        }
    }
    
    // 4. Para cada libreria, reservar espacio para el nombre de la DLL (cadena + terminador)
    _DWORD sizeDllNames = 0;
    for (int i = 0; i < numLibs; i++) {
        sizeDllNames += (_DWORD)strlen(libs[i].dllName) + 1;
    }
    
    // Tamaño total del buffer
    _DWORD totalSize = sizeImportDir + sizeILT_IAT + sizeHintName + sizeDllNames;
    _BYTE* buffer = calloc(1, totalSize);
    if (!buffer) 
        return NULL;

    // Reservamos áreas consecutivas:
    //  [0, sizeImportDir): Import Directory Table
    //  [sizeImportDir, sizeImportDir + sizeILT_IAT): ILT + IAT para todas las librerias
    //  [sizeImportDir + sizeILT_IAT, sizeImportDir + sizeILT_IAT + sizeHintName): Hint/Name tables
    //  [sizeImportDir + sizeILT_IAT + sizeHintName, totalSize): DLL names
    _DWORD importDirOffset = 0;
    _DWORD iltIatOffset = importDirOffset + sizeImportDir;
    _DWORD hintNameOffset = iltIatOffset + sizeILT_IAT;
    _DWORD dllNameOffset = hintNameOffset + sizeHintName;
    
    // Construir Import Directory Table
    ___IMAGE_IMPORT_DESCRIPTOR* importDir = (___IMAGE_IMPORT_DESCRIPTOR*)(buffer + importDirOffset);
    // Variable para ir avanzando en la region ILT/IAT
    _DWORD currentILT_IAT = iltIatOffset;
    for (int i = 0; i < numLibs; i++) {
        int numFuncs = libs[i].numFunctions;
        _DWORD thisILT = currentILT_IAT;
        _DWORD thisIAT = currentILT_IAT + (numFuncs + 1) * sizeof(_QWORD);
        
        // Configurar descriptor para la libreria i
        importDir[i].DUMMYUNIONNAME__.OriginalFirstThunk = idataRVA + thisILT;
        importDir[i].TimeDateStamp = 0;
        importDir[i].ForwarderChain = 0;
        importDir[i].Name = idataRVA + dllNameOffset; // Ubicacion del nombre de la DLL
        importDir[i].FirstThunk = idataRVA + thisIAT;
        
        // Llenar ILT e IAT para esta libreria
        _QWORD* iltArray = (_QWORD*)(buffer + thisILT);
        _QWORD* iatArray = (_QWORD*)(buffer + thisIAT);
        for (int j = 0; j < numFuncs; j++) {
            // En cada entrada ILT/IAT se almacena el RVA a la entrada Hint/Name para la funcion
            // Nota: Si se desea que apunte directamente al nombre 
            // (omitiendo el WORD hint), se podria sumar sizeof(WORD)
            iltArray[j] = idataRVA + hintNameOffset;
            iatArray[j] = idataRVA + hintNameOffset;
            
            // Escribir Hint/Name: WORD (hint, 0) + nombre de la funcion
            _WORD hint = 0;
            memcpy(buffer + hintNameOffset, &hint, sizeof(_WORD));
            hintNameOffset += sizeof(_WORD);
            strcpy((char*)(buffer + hintNameOffset), libs[i].functions[j]);
            hintNameOffset += (_DWORD)strlen(libs[i].functions[j]) + 1;
        }
        // Terminador de la ILT e IAT
        iltArray[numFuncs] = 0;
        iatArray[numFuncs] = 0;
        
        // Actualizar currentILT_IAT para la siguiente libreria:
        currentILT_IAT += (numFuncs + 1) * sizeof(_QWORD) * 2;
        
        // Escribir el nombre de la DLL
        strcpy((char*)(buffer + dllNameOffset), libs[i].dllName);
        dllNameOffset += (_DWORD)strlen(libs[i].dllName) + 1;
    }
    // Descriptor nulo final de la Import Directory Table
    memset(&importDir[numLibs], 0, sizeof(___IMAGE_IMPORT_DESCRIPTOR));
    
    if (outSize) 
        *outSize = totalSize;
    return buffer;
}

// Genera un buffer que contiene una tabla de importaciones para un entry (funcion y DLL)
// Se calcula internamente el layout de: Import Directory, ILT, IAT, Hint/Name y nombre de DLL.
// Construye la seccion .idata para importar una funcion desde una DLL
_BYTE* buildIdataSection(const char* funcName, const char* dllName, _DWORD idataRVA, _DWORD* outSize) {
    _DWORD impDescSize = sizeof(___IMAGE_IMPORT_DESCRIPTOR);
    _DWORD importLookupTableRVA = impDescSize * 2;
    _DWORD importAddressTableRVA = importLookupTableRVA + sizeof(_QWORD) * 2;
    _DWORD hintNameTableRVA = importAddressTableRVA + sizeof(_QWORD) * 2;
    _DWORD dllNameRVA = hintNameTableRVA + sizeof(_WORD) + (_DWORD)strlen(funcName) + 1;
    _DWORD totalSize = dllNameRVA + (_DWORD)strlen(dllName) + 1;
    
    _BYTE* buffer = calloc(1, totalSize);
    if (!buffer) return NULL;
    
    _DWORD offset = 0;
    
    // Import Directory Table
    ___IMAGE_IMPORT_DESCRIPTOR importDescriptor = {
        .DUMMYUNIONNAME__.OriginalFirstThunk = idataRVA + importLookupTableRVA,
        .TimeDateStamp = 0,
        .ForwarderChain = 0,
        .Name = idataRVA + dllNameRVA,
        .FirstThunk = idataRVA + importAddressTableRVA
    };
    memcpy(buffer + offset, &importDescriptor, impDescSize);
    offset += impDescSize * 2; // Include null terminator
    
    // Import Lookup Table (ILT)
    _QWORD iltEntry = idataRVA + hintNameTableRVA;
    memcpy(buffer + offset, &iltEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD) * 2; // Include null terminator
    
    // Import Address Table (IAT)
    memcpy(buffer + offset, &iltEntry, sizeof(_QWORD));
    offset += sizeof(_QWORD) * 2; // Include null terminator
    
    // Hint/Name Table
    _WORD hint = 0;
    memcpy(buffer + offset, &hint, sizeof(_WORD));
    offset += sizeof(_WORD);
    strcpy((char*)(buffer + offset), funcName);
    offset += strlen(funcName) + 1;
    
    // DLL name
    strcpy((char*)(buffer + offset), dllName);
    offset += strlen(dllName) + 1;
    
    if (outSize) *outSize = totalSize;
    return buffer;
}



// Funcion para calcular el desplazamiento (disp32) para una instruccion call con direccionamiento RIP-relative
int32_t calcularDesplazamientoCall(uint64_t direccionInstruccion, uint64_t direccionDestino) {
    return (int32_t)(direccionDestino - direccionInstruccion);
}
// Funcion para corregir todas las instrucciones 'call' en una seccion de codigo
void corregirDesplazamientosCall(
    uint8_t* codigo, size_t tamanoCodigo, 
    uint64_t baseVirtualSeccion, uint64_t direccionIAT, FunctionOffset* funcOffsets, int numFunciones) {
    int callIndex = 0;
    for (size_t i = 0; i < tamanoCodigo - 5; i++) {
        // Buscar la instruccion 'call' (opcode 0xFF 0x15)
        if (codigo[i] == 0xFF && codigo[i+1] == 0x15) {
            if (callIndex < numFunciones) {
                // Direccion virtual de la instruccion siguiente al 'call'
                uint64_t direccionInstruccionSiguiente = baseVirtualSeccion + i + 6;
                // Calcular el desplazamiento, incluyendo el offset de la funcion en la IAT
                int32_t desplazamiento = calcularDesplazamientoCall(
                    direccionInstruccionSiguiente, direccionIAT + funcOffsets[callIndex].offset);
                // Escribir el desplazamiento en el lugar correspondiente
                memcpy(&codigo[i + 2], &desplazamiento, sizeof(int32_t));
                callIndex++;
            }
        }
    }
}



void finalizePE64File(PE64FILE_struct* pe) {
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = align(sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                                                         (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)),
                                                         FILE_ALIGN);
    pe->ntHeaders.OptionalHeader.AddressOfEntryPoint = pe->sectionHeaders[0].VirtualAddress;
    pe->ntHeaders.OptionalHeader.BaseOfCode = pe->sectionHeaders[0].VirtualAddress;
    pe->ntHeaders.OptionalHeader.SizeOfCode = 0;
    pe->ntHeaders.OptionalHeader.SizeOfInitializedData = 0;
    for (int i = 0; i < pe->numberOfSections; i++) {
        if (pe->sectionHeaders[i].Characteristics & ___IMAGE_SCN_CNT_CODE)
            pe->ntHeaders.OptionalHeader.SizeOfCode += pe->sectionHeaders[i].SizeOfRawData;
        if (pe->sectionHeaders[i].Characteristics & ___IMAGE_SCN_CNT_INITIALIZED_DATA)
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
    _DWORD headerPadding = pe->ntHeaders.OptionalHeader.SizeOfHeaders -
                          (sizeof(___IMAGE_DOS_HEADER) + sizeof(___IMAGE_NT_HEADERS64) +
                           (pe->numberOfSections * sizeof(___IMAGE_SECTION_HEADER)));
    _BYTE* padding = calloc(1, headerPadding);
    fwrite(padding, 1, headerPadding, fileHandle);
    free(padding);
    for (int i = 0; i < pe->numberOfSections; i++) {
        fseek(fileHandle, pe->sectionHeaders[i].PointerToRawData, SEEK_SET);
        fwrite(pe->sectionData[i], 1, pe->sectionHeaders[i].SizeOfRawData, fileHandle);
    }
    fclose(fileHandle);
}

void freePE64File(PE64FILE_struct* pe) {
    if (pe->sectionHeaders) free(pe->sectionHeaders);
    if (pe->sectionData) {
        for (int i = 0; i < pe->numberOfSections; i++) {
            free(pe->sectionData[i]);
        }
        free(pe->sectionData);
    }
}