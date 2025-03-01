#include "./src/LibPEparse.c"

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pe_file_path>\n", argv[0]);
        return 1;
    }
    
    FILE *pe_file_path = NULL;
    if ((pe_file_path = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening file: %s\n", argv[1]);
        return 1;
    }
    
    printf("pe_file path: %s\n", pe_file_path);
    PE64FILE *file = PE64FILE_Create("programa.exe", pe_file_path);

    PE64FILE_PrintInfo64(file);

    puts("exit...");
    return 0;
}