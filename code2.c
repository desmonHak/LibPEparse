#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "./src/LibPEparse.c"

#define IMAGE_BASE 0x400000
#define SECT_ALIGN 0x1000
#define FILE_ALIGN 0x200

// Estructura para el archivo PE (simplificada)
typedef struct {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_SECTION_HEADER* sectionHeaders;
    BYTE** sectionData;
    int numberOfSections;
} PE64FILE_struct;

// Estructura para representar una librería y sus funciones a importar
typedef struct {
    const char* dllName;      // Ej: "KERNEL32.dll"
    const char** functions;   // Ej: { "ExitProcess", "WriteConsoleA" }
    int numFunctions;         // Número de funciones en el array
} ImportLibrary;

// Estructura para mapear offsets de funciones
typedef struct {
    int offset;
    const char* name;
} FunctionOffset;

// Prototipos de funciones auxiliares y de extensión
void initializePE64File(PE64FILE_struct* pe);
int addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, BYTE* data, _DWORD dataSize);
int getSectionIndex(PE64FILE_struct* pe, const char* name);
void appendToSection(PE64FILE_struct* pe, const char* name, BYTE* data, _DWORD dataSize);
void addBssSection(PE64FILE_struct* pe, const char* name, _DWORD size);
BYTE* buildIdataSection(const char* funcName, const char* dllName, _DWORD idataRVA, _DWORD* outSize);
void finalizePE64File(PE64FILE_struct* pe);
void writePE64File(PE64FILE_struct* pe, const char* filename);
void freePE64File(PE64FILE_struct* pe);

// Inicializa la estructura PE con headers mínimos
void initializePE64File(PE64FILE_struct* pe) {
    memset(pe, 0, sizeof(PE64FILE_struct));
    // DOS Header
    pe->dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
    pe->dosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);
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
    pe->ntHeaders.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                      IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                                      IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    pe->ntHeaders.OptionalHeader.SizeOfStackReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfStackCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapReserve = 0x100000;
    pe->ntHeaders.OptionalHeader.SizeOfHeapCommit = 0x1000;
    pe->ntHeaders.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = 0x400; // Valor inicial mayor
}

// Agrega una nueva sección al PE y retorna su índice
int addSection(PE64FILE_struct* pe, const char* name, _DWORD characteristics, BYTE* data, _DWORD dataSize) {
    pe->numberOfSections++;
    pe->sectionHeaders = realloc(pe->sectionHeaders, pe->numberOfSections * sizeof(IMAGE_SECTION_HEADER));
    pe->sectionData = realloc(pe->sectionData, pe->numberOfSections * sizeof(BYTE*));

    IMAGE_SECTION_HEADER* newSection = &pe->sectionHeaders[pe->numberOfSections - 1];
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    strncpy((char*)newSection->Name, name, IMAGE_SIZEOF_SHORT_NAME);

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
        newSection->PointerToRawData = align(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) +
                                              (pe->numberOfSections * sizeof(IMAGE_SECTION_HEADER)),
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

// Retorna el índice de una sección buscada por su nombre (o -1 si no se encuentra)
int getSectionIndex(PE64FILE_struct* pe, const char* name) {
    for (int i = 0; i < pe->numberOfSections; i++) {
        if (strncmp((char*)pe->sectionHeaders[i].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return i;
    }
    return -1;
}

// Anexa nuevos datos a una sección existente (por ejemplo, para agregar código a .text)
void appendToSection(PE64FILE_struct* pe, const char* name, BYTE* data, _DWORD dataSize) {
    int index = getSectionIndex(pe, name);
    if (index < 0) return;
    _DWORD currentSize = pe->sectionHeaders[index].Misc.VirtualSize;
    _DWORD newSize = currentSize + dataSize;
    BYTE* newBuffer = realloc(pe->sectionData[index], align(newSize, FILE_ALIGN));
    if (!newBuffer) return;
    memcpy(newBuffer + currentSize, data, dataSize);
    pe->sectionData[index] = newBuffer;
    pe->sectionHeaders[index].Misc.VirtualSize = newSize;
    pe->sectionHeaders[index].SizeOfRawData = align(newSize, FILE_ALIGN);
}

// Agrega una sección .bss (datos no inicializados) generando un buffer de ceros
void addBssSection(PE64FILE_struct* pe, const char* name, _DWORD size) {
    BYTE* zeroBuffer = calloc(1, size);
    addSection(pe, name, IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, zeroBuffer, size);
    free(zeroBuffer);
}

// Construye una sección .idata con múltiples entradas de importación
// Parámetros:
//   libs: array de ImportLibrary
//   numLibs: cantidad de librerías
//   idataRVA: RVA base en la sección .idata donde se ubicará el contenido
//   outSize: tamaño total del buffer generado (salida)
BYTE* buildMultiIdataSection(ImportLibrary* libs, int numLibs, _DWORD idataRVA, _DWORD* outSize) {
    // 1. Tamaño de la Import Directory Table (una descriptor por librería + uno nulo)
    _DWORD sizeImportDir = (numLibs + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    
    // 2. Para cada librería se reservará ILT e IAT:
    _DWORD sizeILT_IAT = 0;
    for (int i = 0; i < numLibs; i++) {
        sizeILT_IAT += (libs[i].numFunctions + 1) * sizeof(_QWORD) * 2; // ILT + IAT
    }
    
    // 3. Para cada función, se necesita espacio para Hint/Name (WORD + cadena + terminador)
    _DWORD sizeHintName = 0;
    for (int i = 0; i < numLibs; i++) {
        for (int j = 0; j < libs[i].numFunctions; j++) {
            sizeHintName += sizeof(WORD) + (_DWORD)strlen(libs[i].functions[j]) + 1;
        }
    }
    
    // 4. Para cada librería, reservar espacio para el nombre de la DLL (cadena + terminador)
    _DWORD sizeDllNames = 0;
    for (int i = 0; i < numLibs; i++) {
        sizeDllNames += (_DWORD)strlen(libs[i].dllName) + 1;
    }
    
    // Tamaño total del buffer
    _DWORD totalSize = sizeImportDir + sizeILT_IAT + sizeHintName + sizeDllNames;
    BYTE* buffer = calloc(1, totalSize);
    if (!buffer) 
        return NULL;
    _DWORD offset = 0;
    
    // Reservamos áreas consecutivas:
    //  [0, sizeImportDir): Import Directory Table
    //  [sizeImportDir, sizeImportDir + sizeILT_IAT): ILT + IAT para todas las librerías
    //  [sizeImportDir + sizeILT_IAT, sizeImportDir + sizeILT_IAT + sizeHintName): Hint/Name tables
    //  [sizeImportDir + sizeILT_IAT + sizeHintName, totalSize): DLL names
    _DWORD importDirOffset = 0;
    _DWORD iltIatOffset = importDirOffset + sizeImportDir;
    _DWORD hintNameOffset = iltIatOffset + sizeILT_IAT;
    _DWORD dllNameOffset = hintNameOffset + sizeHintName;
    
    // Construir Import Directory Table
    IMAGE_IMPORT_DESCRIPTOR* importDir = (IMAGE_IMPORT_DESCRIPTOR*)(buffer + importDirOffset);
    // Variable para ir avanzando en la región ILT/IAT
    _DWORD currentILT_IAT = iltIatOffset;
    for (int i = 0; i < numLibs; i++) {
        int numFuncs = libs[i].numFunctions;
        _DWORD thisILT = currentILT_IAT;
        _DWORD thisIAT = currentILT_IAT + (numFuncs + 1) * sizeof(_QWORD);
        
        // Configurar descriptor para la librería i
        importDir[i].OriginalFirstThunk = idataRVA + thisILT;
        importDir[i].TimeDateStamp = 0;
        importDir[i].ForwarderChain = 0;
        importDir[i].Name = idataRVA + dllNameOffset; // Ubicación del nombre de la DLL
        importDir[i].FirstThunk = idataRVA + thisIAT;
        
        // Llenar ILT e IAT para esta librería
        _QWORD* iltArray = (_QWORD*)(buffer + thisILT);
        _QWORD* iatArray = (_QWORD*)(buffer + thisIAT);
        for (int j = 0; j < numFuncs; j++) {
            // En cada entrada ILT/IAT se almacena el RVA a la entrada Hint/Name para la función
            // Nota: Si se desea que apunte directamente al nombre (omitiendo el WORD hint), se podría sumar sizeof(WORD)
            iltArray[j] = idataRVA + hintNameOffset;
            iatArray[j] = idataRVA + hintNameOffset;
            
            // Escribir Hint/Name: WORD (hint, 0) + nombre de la función
            WORD hint = 0;
            memcpy(buffer + hintNameOffset, &hint, sizeof(WORD));
            hintNameOffset += sizeof(WORD);
            strcpy((char*)(buffer + hintNameOffset), libs[i].functions[j]);
            hintNameOffset += (_DWORD)strlen(libs[i].functions[j]) + 1;
        }
        // Terminador de la ILT e IAT
        iltArray[numFuncs] = 0;
        iatArray[numFuncs] = 0;
        
        // Actualizar currentILT_IAT para la siguiente librería:
        currentILT_IAT += (numFuncs + 1) * sizeof(_QWORD) * 2;
        
        // Escribir el nombre de la DLL
        strcpy((char*)(buffer + dllNameOffset), libs[i].dllName);
        dllNameOffset += (_DWORD)strlen(libs[i].dllName) + 1;
    }
    // Descriptor nulo final de la Import Directory Table
    memset(&importDir[numLibs], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    
    if (outSize) 
        *outSize = totalSize;
    return buffer;
}

// Genera un buffer que contiene una tabla de importaciones para un entry (función y DLL)
// Se calcula internamente el layout de: Import Directory, ILT, IAT, Hint/Name y nombre de DLL.
// Construye la sección .idata para importar una función desde una DLL
BYTE* buildIdataSection(const char* funcName, const char* dllName, _DWORD idataRVA, _DWORD* outSize) {
    _DWORD impDescSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    _DWORD importLookupTableRVA = impDescSize * 2;
    _DWORD importAddressTableRVA = importLookupTableRVA + sizeof(_QWORD) * 2;
    _DWORD hintNameTableRVA = importAddressTableRVA + sizeof(_QWORD) * 2;
    _DWORD dllNameRVA = hintNameTableRVA + sizeof(WORD) + (_DWORD)strlen(funcName) + 1;
    _DWORD totalSize = dllNameRVA + (_DWORD)strlen(dllName) + 1;
    
    BYTE* buffer = calloc(1, totalSize);
    if (!buffer) return NULL;
    
    _DWORD offset = 0;
    
    // Import Directory Table
    IMAGE_IMPORT_DESCRIPTOR importDescriptor = {
        .OriginalFirstThunk = idataRVA + importLookupTableRVA,
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
    WORD hint = 0;
    memcpy(buffer + offset, &hint, sizeof(WORD));
    offset += sizeof(WORD);
    strcpy((char*)(buffer + offset), funcName);
    offset += strlen(funcName) + 1;
    
    // DLL name
    strcpy((char*)(buffer + offset), dllName);
    offset += strlen(dllName) + 1;
    
    if (outSize) *outSize = totalSize;
    return buffer;
}



// Función para calcular el desplazamiento (disp32) para una instrucción call con direccionamiento RIP-relative
int32_t calcularDesplazamientoCall(uint64_t direccionInstruccion, uint64_t direccionDestino) {
    return (int32_t)(direccionDestino - direccionInstruccion);
}
// Función para corregir todas las instrucciones 'call' en una sección de código
void corregirDesplazamientosCall(uint8_t* codigo, size_t tamanoCodigo, uint64_t baseVirtualSeccion, uint64_t direccionIAT, FunctionOffset* funcOffsets, int numFunciones) {
    int callIndex = 0;
    for (size_t i = 0; i < tamanoCodigo - 5; i++) {
        // Buscar la instrucción 'call' (opcode 0xFF 0x15)
        if (codigo[i] == 0xFF && codigo[i+1] == 0x15) {
            if (callIndex < numFunciones) {
                // Dirección virtual de la instrucción siguiente al 'call'
                uint64_t direccionInstruccionSiguiente = baseVirtualSeccion + i + 6;
                // Calcular el desplazamiento, incluyendo el offset de la función en la IAT
                int32_t desplazamiento = calcularDesplazamientoCall(direccionInstruccionSiguiente, direccionIAT + funcOffsets[callIndex].offset);
                // Escribir el desplazamiento en el lugar correspondiente
                memcpy(&codigo[i + 2], &desplazamiento, sizeof(int32_t));
                callIndex++;
            }
        }
    }
}



void finalizePE64File(PE64FILE_struct* pe) {
    pe->ntHeaders.OptionalHeader.SizeOfHeaders = align(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) +
                                                         (pe->numberOfSections * sizeof(IMAGE_SECTION_HEADER)),
                                                         FILE_ALIGN);
    pe->ntHeaders.OptionalHeader.AddressOfEntryPoint = pe->sectionHeaders[0].VirtualAddress;
    pe->ntHeaders.OptionalHeader.BaseOfCode = pe->sectionHeaders[0].VirtualAddress;
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
    fwrite(&pe->dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fileHandle);
    fwrite(&pe->ntHeaders, sizeof(IMAGE_NT_HEADERS64), 1, fileHandle);
    fwrite(pe->sectionHeaders, sizeof(IMAGE_SECTION_HEADER), pe->numberOfSections, fileHandle);
    _DWORD headerPadding = pe->ntHeaders.OptionalHeader.SizeOfHeaders -
                          (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) +
                           (pe->numberOfSections * sizeof(IMAGE_SECTION_HEADER)));
    BYTE* padding = calloc(1, headerPadding);
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

int main() {
    PE64FILE_struct pe;
    initializePE64File(&pe);

    // 1. Agregar sección .text con código inicial
    BYTE textCode[] = {
        0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 40h
        0x48, 0x33, 0xC9,                           // xor rcx, rcx
        0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,   // lea rdx, [rip + offset_to_message]
        0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,   // lea r8, [rip + offset_to_caption]
        0x4D, 0x33, 0xC9,                           // xor r9, r9
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,         // call [RIP+disp32] (MessageBoxA)
        0x48, 0x33, 0xC9,                           // xor rcx, rcx
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,         // call [RIP+disp32] (ExitProcess)
        0xEB, 0xFE                                  // jmp $
    };
    
    
    int textIndex = addSection(&pe, ".text", IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
                               textCode, sizeof(textCode));

    // 2. Construir la sección .idata para importar "ExitProcess" de "KERNEL32.dll"
    // Declaración de las librerías a importar
    const char* kernel32Funcs[] = { "ExitProcess", "WriteConsoleA" };
    const char* user32Funcs[]   = { "MessageBoxA" };

    ImportLibrary libs[] = {
        { "KERNEL32.dll", kernel32Funcs, sizeof(kernel32Funcs) / sizeof(kernel32Funcs[0]) },
        { "USER32.dll",   user32Funcs,   sizeof(user32Funcs) / sizeof(user32Funcs[0]) }
    };

    int numLibs = sizeof(libs) / sizeof(libs[0]);

    // Asumiendo que la sección .idata se ubicará en RVA = SECT_ALIGN * 2 (por ejemplo, 0x2000)
    _DWORD idataRVA = SECT_ALIGN * 2;
    _DWORD idataSize = 0;
    BYTE* idataBuffer = buildMultiIdataSection(libs, numLibs, idataRVA, &idataSize);

    // Agregar la sección .idata al PE
    int idataIndex = addSection(&pe, ".idata",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        idataBuffer, idataSize);
    free(idataBuffer);

    // necesario para la sección .idata y la IAT
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataRVA;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = idataRVA + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2 + sizeof(_QWORD) * 2;
    pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = sizeof(_QWORD) * 2;

    // 3. Corregir el target del call en .text
    uint8_t* codigoTexto = pe.sectionData[textIndex];
    size_t tamanoCodigoTexto = pe.sectionHeaders[textIndex].Misc.VirtualSize;
    uint64_t baseVirtualTexto = pe.sectionHeaders[textIndex].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;
    uint64_t direccionIAT = pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;

    FunctionOffset stack_functions_offsets[] = {
        // 10 bytes (descriptor de KERNEL32.dll) +
        // 10 bytes (descriptor de USER32.dll) +
        // 8 bytes (primeros bytes de la tabla de nombres) = 28 bytes
        {68, "MessageBoxA"},
        {28, "ExitProcess"},
        {36, "WriteConsoleA"}
    };

    corregirDesplazamientosCall(
        codigoTexto, tamanoCodigoTexto, 
        baseVirtualTexto, direccionIAT, 
        stack_functions_offsets, 
        sizeof(stack_functions_offsets) / sizeof(stack_functions_offsets[0])
    );

    // 4. Anexar código extra a la sección .text (por ejemplo, tres NOPs)
    BYTE extraCode[] = { 0x90, 0x90, 0x90 };
    appendToSection(&pe, ".text", extraCode, sizeof(extraCode));
    

    // 4.5 Anexar sección .data 
    const char message[] = "Hello, World!";
    const char caption[] = "Message";

    BYTE dataSection[512] = {0};  // Aumentamos el tamaño para asegurar alineación
    memcpy(dataSection, message, strlen(message) + 1);
    memcpy(dataSection + strlen(message) + 1, caption, strlen(caption) + 1);

    int dataIndex = addSection(&pe, ".data", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                            dataSection, sizeof(dataSection));



    // 5. Agregar una sección .bss (datos no inicializados)
    addBssSection(&pe, ".bss", 0x100); // 256 bytes

    // 6. Establecer AddressOfEntryPoint al inicio de .text y actualizar SizeOfImage
    pe.ntHeaders.OptionalHeader.AddressOfEntryPoint = SECT_ALIGN;
    pe.ntHeaders.OptionalHeader.SizeOfImage = align(pe.sectionHeaders[pe.numberOfSections - 1].VirtualAddress +
                                                     pe.sectionHeaders[pe.numberOfSections - 1].Misc.VirtualSize,
                                                     pe.ntHeaders.OptionalHeader.SectionAlignment);


    // Calcular y corregir los desplazamientos
    codigoTexto = pe.sectionData[textIndex];
    baseVirtualTexto = pe.sectionHeaders[textIndex].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;
    uint64_t baseVirtualData = pe.sectionHeaders[dataIndex].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;

    // Calcular desplazamientos relativos
    // Los desplazamientos son calculados utilizando:
    // baseVirtualData + (offsets de todos los datos hasta ese campo) - ( baseVirtualTexto + (
    // offsets de todos los datos hasta ese campo + datos de este campo))
    int32_t offsetToMessage = (int32_t)(baseVirtualData + (0                  ) - (baseVirtualTexto + 0x0E));
    int32_t offsetToCaption = (int32_t)(baseVirtualData + (strlen(message) + 1) - (baseVirtualTexto + 0x15));



    printf("baseVirtualTexto %p baseVirtualData %p\n", (void*)baseVirtualTexto, (void*)baseVirtualData);
    printf("offsetToMessage = %d offsetToCaption = %d\n", offsetToMessage, offsetToCaption);
    // Corregir los desplazamientos en el código
    *(int32_t*)(codigoTexto + 10) = offsetToMessage;
    *(int32_t*)(codigoTexto + 17) = offsetToCaption;



    finalizePE64File(&pe);
    writePE64File(&pe, "nuevo_pe_desde_cero.exe");
    freePE64File(&pe);

    // Opcional: Imprimir información del PE usando funciones de LibPEparse
    PE64FILE *file = PE64FILE_Create("nuevo_pe_desde_cero.exe", fopen("nuevo_pe_desde_cero.exe", "rb"));
    PE64FILE_PrintInfo64(file);

    printf("PE file created successfully.\n");
    return 0;
}
