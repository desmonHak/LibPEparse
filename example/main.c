#include "LibPEparse.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pe_file_path>\n", argv[0]);
        return 1;
    }

    FILE *pe_file_path = NULL;
    if ((pe_file_path = fopen(argv[1], "rb")) == NULL) { // Importante: abrir en modo binario
        fprintf(stderr, "Error opening file: %s\n", argv[1]);
        return 1;
    }

    printf("pe_file path: %s\n", argv[1]);
    PE64FILE *file = PE64FILE_Create("programa.exe", pe_file_path);

    // Añadir una nueva sección
    char newSectionData[] = "Esto es una nueva sección";
    _DWORD newSectionSize = sizeof(newSectionData);
    AddNewSection64(file, ".newsec1", newSectionSize, newSectionData, SECTION_TYPE_CODE);

    // Escribir el archivo PE modificado
    WriteModifiedPEFile64(file, "nuevo_archivo.exe", ".newsec1", newSectionSize);

    AddNewSection64(file, ".newsec2", newSectionSize, newSectionData, SECTION_TYPE_CODE);
    WriteModifiedPEFile64(file, "nuevo_archivo.exe", ".newsec2", newSectionSize);
    PE64FILE_PrintInfo64(file);
    PE64FILE_Destroy(file);

    memset(file, 0, sizeof(PE64FILE));
    file = PE64FILE_Create("nuevo_archivo.exe", pe_file_path);
    PE64FILE_PrintInfo64(file);
    PE64FILE_Destroy(file);

    puts("exit...");

    return 0;
}