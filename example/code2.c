#include "CreatePe.h"

#include <string.h>

int main() {
    PE64FILE_struct pe;
    initializePE64File(&pe);

    // 1. Agregar seccion .text con codigo inicial
    _BYTE textCode[] = {
        /*00*/ 0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 40h
        /*04*/ 0x48, 0x33, 0xC9,                           // xor rcx, rcx
        /*07*/ 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,   // lea rdx, [rip + offset_to_message]
        /*14*/ 0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,   // lea r8, [rip + offset_to_caption]
        /*21*/ 0x4D, 0x33, 0xC9,                           // xor r9, r9
        /*24*/ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,         // call [RIP+disp32] (MessageBoxA)
        /*30*/ 0x48, 0x33, 0xC9,                           // xor rcx, rcx
        /*33*/ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,         // call [RIP+disp32] (ExitProcess)
        /*39*/ 0xEB, 0xFE                                  // jmp $
    };
    
    
    int textIndex = addSection(&pe, ".text", ___IMAGE_SCN_CNT_CODE | ___IMAGE_SCN_MEM_EXECUTE | ___IMAGE_SCN_MEM_READ,
                               textCode, sizeof(textCode));

    // 2. Construir la seccion .idata para importar "ExitProcess" de "KERNEL32.dll"
    // Declaracion de las librerias a importar
    const char* kernel32Funcs[] = { "ExitProcess", "WriteConsoleA" };
    const char* user32Funcs[]   = { "MessageBoxA" };

    /**
     * La región ILT/IAT para cada DLL ocupa (numFuncs + 1) * sizeof(_QWORD) * 2
     * bytes por DLL (porque cada función tiene una entrada en ILT y otra en IAT, más un terminador).
     */
    ImportLibrary libs[] = {
        { "KERNEL32.dll", kernel32Funcs, sizeof(kernel32Funcs) / sizeof(kernel32Funcs[0]) },
        { "USER32.dll",   user32Funcs,   sizeof(user32Funcs) / sizeof(user32Funcs[0]) }
    };

    int numLibs = sizeof(libs) / sizeof(libs[0]);

    // Asumiendo que la seccion .idata se ubicará en RVA = SECT_ALIGN * 2 (por ejemplo, 0x2000)
    _DWORD idataRVA = SECT_ALIGN * 2;
    _DWORD idataSize = 0;
    ImportOffsetEntry* offsets = NULL;
    int numOffsets = 0;
    _BYTE* idataBuffer = buildMultiIdataSectionWithOffsets(
        libs, numLibs, idataRVA, &idataSize, &offsets, &numOffsets
    );

    // Ahora usar offsets[i].offset para cada función importada
    for (int i = 0; i < numOffsets; i++) {
        printf("Función %s (DLL %s) offset en IAT: %d\n", offsets[i].functionName, offsets[i].dllName, offsets[i].offset);
    }

    // Agregar la seccion .idata al PE
    int idataIndex = addSection(&pe, ".idata",
        ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE,
        idataBuffer, idataSize);
    free(idataBuffer);

    // necesario para la seccion .idata y la IAT
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

    //FunctionOffset stack_functions_offsets[] = {
    //    // 10 bytes (descriptor de KERNEL32.dll) +
    //    // 10 bytes (descriptor de USER32.dll) +
    //    // 8 bytes (primeros bytes de la tabla de nombres) = 28 bytes
    //    (FunctionOffset){
    //        68,  24, "MessageBoxA"
    //    }, // offset_code indica donde debe ponerse la direccion de la funcion en el codigo
    //    {
    //        28, 34, "ExitProcess"},
    //    //{36, 0x0, "WriteConsoleA"}
    //};

    // en este caso, nuestro codigo solo usa una vez MessageBoxA y ExitProcess, asi que
    // solo debemos parchear dos instrucciones:
    /**
     * Función ExitProcess (DLL KERNEL32.dll) offset en IAT: 28
     * Función WriteConsoleA (DLL KERNEL32.dll) offset en IAT: 36
     * Función MessageBoxA (DLL USER32.dll) offset en IAT: 68
     */
    size_t numero_direciones_parchear = 2; // cantidad de direcciones que debemos parchear
    FunctionOffset* stack_functions_offsets = calloc(2, sizeof(FunctionOffset));

    // la primera llamada(stack_functions_offsets[0]) sera MessageBoxA(offsets[2])
    stack_functions_offsets[0].offset_iat   = offsets[2].offset;
    stack_functions_offsets[0].name         = offsets[2].functionName;
    stack_functions_offsets[0].offset_code  = 24; // parchear la direccion offset 24
    printf("Parcheando %p con %s\n", baseVirtualTexto + 24, offsets[2].functionName);

    // la segunda llamada(stack_functions_offsets[1]) sera ExitProcess(offsets[0])
    stack_functions_offsets[1].offset_iat   = offsets[0].offset;
    stack_functions_offsets[1].name         = offsets[0].functionName;
    stack_functions_offsets[1].offset_code  = 34; // parchear la direccion offset 34
    printf("Parcheando %p con %s\n", baseVirtualTexto + 34, offsets[0].functionName);


    parchearDesplazamientosPorOffset(codigoTexto, tamanoCodigoTexto,
        baseVirtualTexto, direccionIAT,
        stack_functions_offsets,
        numero_direciones_parchear);


    // 4. Anexar codigo extra a la seccion .text (por ejemplo, tres NOPs)
    _BYTE extraCode[] = { 0x90, 0x90, 0x90 };
    appendToSection(&pe, ".text", extraCode, sizeof(extraCode));
    

    // 4.5 Anexar seccion .data 
    const char message[] = "Hello, World!";
    const char caption[] = "Message";

    _BYTE dataSection[512] = {0};  // Aumentamos el tamaño para asegurar alineacion
    memcpy(dataSection, message, strlen(message) + 1);
    memcpy(dataSection + strlen(message) + 1, caption, strlen(caption) + 1);

    int dataIndex = addSection(&pe, ".data", 
        ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE,
                            dataSection, sizeof(dataSection));



    // 5. Agregar una seccion .bss (datos no inicializados)
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
    // Corregir los desplazamientos en el codigo
    *(int32_t*)(codigoTexto + 10) = offsetToMessage;
    *(int32_t*)(codigoTexto + 17) = offsetToCaption;



    finalizePE64File(&pe);
    writePE64File(&pe, "nuevo_pe_desde_cero.exe");
    freePE64File(&pe);

    // Opcional: Imprimir informacion del PE usando funciones de LibPEparse
    PE64FILE *file = PE64FILE_Create("nuevo_pe_desde_cero.exe", fopen("nuevo_pe_desde_cero.exe", "rb"));
    PE64FILE_PrintInfo64(file);

    printf("PE file created successfully.\n");
    return 0;
}
