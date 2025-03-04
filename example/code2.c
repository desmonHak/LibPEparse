#include "CreatePe.h"

int main() {
    PE64FILE_struct pe;
    initializePE64File(&pe);

    // 1. Agregar sección .text con código inicial
    _BYTE textCode[] = {
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
    
    
    int textIndex = addSection(&pe, ".text", ___IMAGE_SCN_CNT_CODE | ___IMAGE_SCN_MEM_EXECUTE | ___IMAGE_SCN_MEM_READ,
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
    _BYTE* idataBuffer = buildMultiIdataSection(libs, numLibs, idataRVA, &idataSize);

    // Agregar la sección .idata al PE
    int idataIndex = addSection(&pe, ".idata",
        ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE,
        idataBuffer, idataSize);
    free(idataBuffer);

    // necesario para la sección .idata y la IAT
    pe.ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataRVA;
    pe.ntHeaders.OptionalHeader.DataDirectory[
        ___IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(___IMAGE_IMPORT_DESCRIPTOR) * 2;
    pe.ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = idataRVA + 
        sizeof(___IMAGE_IMPORT_DESCRIPTOR) * 2 + sizeof(_QWORD) * 2;
    pe.ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT].Size = sizeof(_QWORD) * 2;

    // 3. Corregir el target del call en .text
    uint8_t* codigoTexto = pe.sectionData[textIndex];
    size_t tamanoCodigoTexto = pe.sectionHeaders[textIndex].Misc.VirtualSize;
    uint64_t baseVirtualTexto = pe.sectionHeaders[textIndex].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;
    uint64_t direccionIAT = pe.ntHeaders.OptionalHeader.DataDirectory[
        ___IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + pe.ntHeaders.OptionalHeader.ImageBase;

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
    _BYTE extraCode[] = { 0x90, 0x90, 0x90 };
    appendToSection(&pe, ".text", extraCode, sizeof(extraCode));
    

    // 4.5 Anexar sección .data 
    const char message[] = "Hello, World!";
    const char caption[] = "Message";

    _BYTE dataSection[512] = {0};  // Aumentamos el tamaño para asegurar alineación
    memcpy(dataSection, message, strlen(message) + 1);
    memcpy(dataSection + strlen(message) + 1, caption, strlen(caption) + 1);

    int dataIndex = addSection(&pe, ".data", 
        ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE,
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
