#include "LibPEparse.h"

// Nueva función para inicializar la estructura PE64FILE
void PE64FILE_Initialize(PE64FILE* peFile) {
    memset(peFile, 0, sizeof(PE64FILE)); // Inicializar todos los campos a 0
    peFile->PEFILE_RICH_HEADER_INFO.size = 0;
}

PE64FILE* PE64FILE_Create(char* _NAME, FILE* Ppefile) {
    PE64FILE* peFile = (PE64FILE*)malloc(sizeof(PE64FILE));
    if (peFile != NULL) {
        PE64FILE_Initialize(peFile); // Inicializar la estructura
        peFile->NAME = _NAME;
        peFile->Ppefile = Ppefile;
        ParseFile64(peFile);
    }
    return peFile;
}

void PE64FILE_Destroy(PE64FILE* peFile) {
    if (peFile != NULL) {
        //Free rich header
        if (peFile->PEFILE_RICH_HEADER_INFO.ptrToBuffer != NULL){
            free(peFile->PEFILE_RICH_HEADER_INFO.ptrToBuffer);
        }
        if (peFile->PEFILE_RICH_HEADER.entries != NULL){
            free(peFile->PEFILE_RICH_HEADER.entries);
        }
        if (peFile->PEFILE_SECTION_HEADERS != NULL){
            free(peFile->PEFILE_SECTION_HEADERS);
        }

        fclose(peFile->Ppefile);
        free(peFile);
    }
}

void PE64FILE_PrintInfo64(PE64FILE* peFile) {
    if (peFile != NULL) {
        PrintDOSHeaderInfo64(peFile);
        PrintRichHeaderInfo64(peFile);
        PrintNTHeadersInfo64(peFile);
        PrintSectionHeadersInfo64(peFile);
        PrintImportTableInfo64(peFile);
        PrintBaseRelocationsInfo64(peFile);
    }
}

void ParseFile64(PE64FILE* peFile) {

	// PARSE DOS HEADER
	ParseDOSHeader64(peFile);

	// PARSE RICH HEADER
	ParseRichHeader64(peFile);

	//PARSE NT HEADERS
	ParseNTHeaders64(peFile);

	// PARSE SECTION HEADERS
	ParseSectionHeaders64(peFile);

	// PARSE IMPORT DIRECTORY
	ParseImportDirectory64(peFile);

	// PARSE BASE RELOCATIONS
	ParseBaseReloc64(peFile);
}

int locate64(PE64FILE* peFile, _DWORD VA) {
    for (int i = 0; i < peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS; i++) {
        _DWORD sectionVA = peFile->PEFILE_SECTION_HEADERS[i].VirtualAddress;
        _DWORD sectionSize = peFile->PEFILE_SECTION_HEADERS[i].Misc.VirtualSize;
        if (VA >= sectionVA && VA < (sectionVA + sectionSize))
            return i;
    }
    return -1;  // No se encontró la sección
}
_DWORD resolve64(PE64FILE* peFile, _DWORD VA, int index) {
    if (index < 0 || index >= peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS)
        return 0;
    return (VA - peFile->PEFILE_SECTION_HEADERS[index].VirtualAddress)
           + peFile->PEFILE_SECTION_HEADERS[index].PointerToRawData;
}

int INITPARSE(FILE* PpeFile) {

	___IMAGE_DOS_HEADER TMP_DOS_HEADER;
	_WORD PEFILE_TYPE;

	fseek(PpeFile, 0, SEEK_SET);
	fread(&TMP_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, PpeFile);

	if (TMP_DOS_HEADER.e_magic != ___IMAGE_DOS_SIGNATURE) {
		printf("Error. Not a PE file.\n");
		return 1;
	}

	fseek(PpeFile, (TMP_DOS_HEADER.e_lfanew + sizeof(_DWORD) + sizeof(___IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&PEFILE_TYPE, sizeof(_WORD), 1, PpeFile);

	if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 32;
	}
	else if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 64;
	}
	else {
		printf("Error while parsing IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.\n");
		return 1;
	}

}
void ParseDOSHeader64(PE64FILE* peFile) {
	fseek(peFile->Ppefile, 0, SEEK_SET);
	fread(&(peFile->PEFILE_DOS_HEADER), sizeof(___IMAGE_DOS_HEADER), 1, peFile->Ppefile);

	peFile->PEFILE_DOS_HEADER_EMAGIC = peFile->PEFILE_DOS_HEADER.e_magic;
	peFile->PEFILE_DOS_HEADER_LFANEW = peFile->PEFILE_DOS_HEADER.e_lfanew;
}

void PrintDOSHeaderInfo64(PE64FILE* peFile) {
	printf(" DOS HEADER:\n");
	printf(" -----------\n\n");

	printf(" Magic: 0x%X\n", peFile->PEFILE_DOS_HEADER_EMAGIC);
	printf(" File address of new exe header: 0x%X\n", peFile->PEFILE_DOS_HEADER_LFANEW);

}

void ParseRichHeader64(PE64FILE* peFile) {
    // Reservar memoria para leer hasta el e_lfanew
    char* dataPtr = malloc(peFile->PEFILE_DOS_HEADER_LFANEW);
    if (dataPtr == NULL) {
        printf("Error al asignar memoria.\n");
        return;
    }

    // Posicionar el puntero del archivo al inicio y leer hasta e_lfanew
    fseek(peFile->Ppefile, 0, SEEK_SET);
    fread(dataPtr, peFile->PEFILE_DOS_HEADER_LFANEW, 1, peFile->Ppefile);

    // Buscar la cadena "Rich" en el buffer leído
    int index_ = -1;
    for (int i = 0; i <= peFile->PEFILE_DOS_HEADER_LFANEW - 4; i++) {
        if (memcmp(dataPtr + i, "Rich", 4) == 0) {
            index_ = i;
            break;
        }
    }

    // Si no se encuentra el encabezado "Rich", salir de la función
    if (index_ == -1) {
        printf("Encabezado 'Rich' no encontrado.\n");
        peFile->PEFILE_RICH_HEADER_INFO.entries = 0;
        free(dataPtr);
        return;
    }

    // Obtener la clave XOR ubicada después de la cadena "Rich"
    char key[4];
    memcpy(key, dataPtr + index_ + 4, 4);

    // Calcular el tamaño del encabezado Rich
    int indexpointer = index_ - 4;
    int RichHeaderSize = 0;
    while (indexpointer >= 0) {
        char tmpchar[4];
        memcpy(tmpchar, dataPtr + indexpointer, 4);
        for (int i = 0; i < 4; i++) {
            tmpchar[i] ^= key[i];
        }
        indexpointer -= 4;
        RichHeaderSize += 4;
        if (tmpchar[0] == 'D' && tmpchar[1] == 'a') {
            break;
        }
    }

    // Leer el encabezado Rich completo
    char* RichHeaderPtr = malloc(RichHeaderSize);
    if (RichHeaderPtr == NULL) {
        printf("Error al asignar memoria para el encabezado Rich.\n");
        free(dataPtr);
        return;
    }
    memcpy(RichHeaderPtr, dataPtr + index_ - RichHeaderSize, RichHeaderSize);

    // Desencriptar el encabezado Rich usando la clave XOR
    for (int i = 0; i < RichHeaderSize; i++) {
        RichHeaderPtr[i] ^= key[i % 4];
    }

    // Almacenar la información del encabezado Rich en la estructura peFile
    peFile->PEFILE_RICH_HEADER_INFO.size = RichHeaderSize;
    peFile->PEFILE_RICH_HEADER_INFO.ptrToBuffer = RichHeaderPtr;
    peFile->PEFILE_RICH_HEADER_INFO.entries = (RichHeaderSize - 16) / 8;

    // Liberar el buffer temporal
    free(dataPtr);

    // Reservar memoria para las entradas del encabezado Rich
    peFile->PEFILE_RICH_HEADER.entries = malloc(sizeof(RICH_HEADER_ENTRY) * peFile->PEFILE_RICH_HEADER_INFO.entries);
    if (peFile->PEFILE_RICH_HEADER.entries == NULL) {
        printf("Error al asignar memoria para las entradas del encabezado Rich.\n");
        free(RichHeaderPtr);
        return;
    }

    // Analizar las entradas del encabezado Rich
    for (int i = 16; i < RichHeaderSize; i += 8) {
        _WORD PRODID = (_WORD)((unsigned char)RichHeaderPtr[i + 3] << 8 | (unsigned char)RichHeaderPtr[i + 2]);
        _WORD BUILDID = (_WORD)((unsigned char)RichHeaderPtr[i + 1] << 8 | (unsigned char)RichHeaderPtr[i]);
        _DWORD USECOUNT = (_DWORD)((unsigned char)RichHeaderPtr[i + 7] << 24 | 
                                (unsigned char)RichHeaderPtr[i + 6] << 16 |
                                (unsigned char)RichHeaderPtr[i + 5] << 8 | (unsigned char)RichHeaderPtr[i + 4]);
        peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 2].prodID = PRODID;
        peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 2].buildID = BUILDID;
        peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 2].useCount = USECOUNT;

        if (i + 8 >= RichHeaderSize) {
            peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 1].prodID = 0x0000;
            peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 1].buildID = 0x0000;
            peFile->PEFILE_RICH_HEADER.entries[(i / 8) - 1].useCount = 0x00000000;
        }
    }

    // Liberar el buffer del encabezado Rich
    free(peFile->PEFILE_RICH_HEADER_INFO.ptrToBuffer);
}


void PrintRichHeaderInfo64(PE64FILE* peFile) {
	
    if (peFile == NULL || peFile->PEFILE_RICH_HEADER_INFO.size == 0) {
        return;
    }
	printf(" RICH HEADER:\n");
	printf(" ------------\n\n");

	for (int i = 0; i < peFile->PEFILE_RICH_HEADER_INFO.entries; i++) {
		printf(" 0x%X 0x%X 0x%X: %d.%d.%d\n",
			peFile->PEFILE_RICH_HEADER.entries[i].buildID,
			peFile->PEFILE_RICH_HEADER.entries[i].prodID,
			peFile->PEFILE_RICH_HEADER.entries[i].useCount,
			peFile->PEFILE_RICH_HEADER.entries[i].buildID,
			peFile->PEFILE_RICH_HEADER.entries[i].prodID,
			peFile->PEFILE_RICH_HEADER.entries[i].useCount);
	}

}

void ParseNTHeaders64(PE64FILE* peFile) {
	fseek(peFile->Ppefile, peFile->PEFILE_DOS_HEADER.e_lfanew, SEEK_SET);
	fread(&(peFile->PEFILE_NT_HEADERS), sizeof(peFile->PEFILE_NT_HEADERS), 1, peFile->Ppefile);

	peFile->PEFILE_NT_HEADERS_SIGNATURE = peFile->PEFILE_NT_HEADERS.Signature;

	peFile->PEFILE_NT_HEADERS_FILE_HEADER_MACHINE = 
        peFile->PEFILE_NT_HEADERS.FileHeader.Machine;
	peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS = 
        peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections;
	peFile->PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER = 
        peFile->PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader;

	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.Magic;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESS_OF_ENTRYPOINT 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASE_OF_CODE 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.ImageBase;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage;
	peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

	peFile->PEFILE_EXPORT_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT];
	peFile->PEFILE_IMPORT_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT];
	peFile->PEFILE_RESOURCE_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_RESOURCE];
	peFile->PEFILE_EXCEPTION_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	peFile->PEFILE_SECURITY_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_SECURITY];
	peFile->PEFILE_BASERELOC_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC];
	peFile->PEFILE_DEBUG_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DEBUG];
	peFile->PEFILE_ARCHITECTURE_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
	peFile->PEFILE_GLOBALPTR_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
	peFile->PEFILE_TLS_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_TLS];
	peFile->PEFILE_LOAD_CONFIG_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	peFile->PEFILE_BOUND_IMPORT_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	peFile->PEFILE_IAT_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT];
	peFile->PEFILE_DELAY_IMPORT_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	peFile->PEFILE_COM_DESCRIPTOR_DIRECTORY 
        = peFile->PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}

void PrintNTHeadersInfo64(PE64FILE* peFile) {
	
	printf(" NT HEADERS:\n");
	printf(" -----------\n\n");

	printf(" PE Signature: 0x%X\n", peFile->PEFILE_NT_HEADERS_SIGNATURE);

	printf("\n File Header:\n\n");
	printf("   Machine: 0x%X\n", peFile->PEFILE_NT_HEADERS_FILE_HEADER_MACHINE);
	printf("   Number of sections: 0x%X\n", peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS);
	printf("   Size of optional header: 0x%X\n", peFile->PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER);

	printf("\n Optional Header:\n\n");
	printf("   Magic: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC);
	printf("   Size of code section: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE);
	printf("   Size of initialized data: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA);
	printf("   Size of uninitialized data: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA);
	printf("   Address of entry point: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESS_OF_ENTRYPOINT);
	printf("   RVA of start of code section: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASE_OF_CODE);
	printf("   Desired image base: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE);
	printf("   Section alignment: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT);
	printf("   File alignment: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT);
	printf("   Size of image: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE);
	printf("   Size of headers: 0x%X\n", peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS);
    printf("\n Data Directories:\n");
	printf("\n   * Export Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_EXPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_EXPORT_DIRECTORY.Size);

	printf("\n   * Import Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_IMPORT_DIRECTORY.Size);

	printf("\n   * Resource Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_RESOURCE_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_RESOURCE_DIRECTORY.Size);

	printf("\n   * Exception Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_EXCEPTION_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_EXCEPTION_DIRECTORY.Size);

	printf("\n   * Security Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_SECURITY_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_SECURITY_DIRECTORY.Size);

	printf("\n   * Base Relocation Table:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_BASERELOC_DIRECTORY.Size);

	printf("\n   * Debug Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_DEBUG_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_DEBUG_DIRECTORY.Size);

	printf("\n   * Architecture Specific Data:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_ARCHITECTURE_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_ARCHITECTURE_DIRECTORY.Size);

	printf("\n   * RVA of GlobalPtr:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_GLOBALPTR_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_GLOBALPTR_DIRECTORY.Size);

	printf("\n   * TLS Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_TLS_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_TLS_DIRECTORY.Size);

	printf("\n   * Load Configuration Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_LOAD_CONFIG_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_LOAD_CONFIG_DIRECTORY.Size);

	printf("\n   * Bound Import Directory:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_BOUND_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_BOUND_IMPORT_DIRECTORY.Size);

	printf("\n   * Import Address Table:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_IAT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_IAT_DIRECTORY.Size);

	printf("\n   * Delay Load Import Descriptors:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_DELAY_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_DELAY_IMPORT_DIRECTORY.Size);

	printf("\n   * COM Runtime Descriptor:\n");
	printf("       RVA: 0x%X\n", peFile->PEFILE_COM_DESCRIPTOR_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", peFile->PEFILE_COM_DESCRIPTOR_DIRECTORY.Size);
}

void ParseSectionHeaders64(PE64FILE * peFile) {
	
	peFile->PEFILE_SECTION_HEADERS = malloc(
        sizeof(___IMAGE_SECTION_HEADER) * 
        peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS
    );
	for (int i = 0; i < peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS; i++) {
		int offset = (
            peFile->PEFILE_DOS_HEADER.e_lfanew + 
            sizeof(peFile->PEFILE_NT_HEADERS)
        ) + (i * ___IMAGE_SIZEOF_SECTION_HEADER);
		fseek(peFile->Ppefile, offset, SEEK_SET);
		fread(&(peFile->PEFILE_SECTION_HEADERS[i]), ___IMAGE_SIZEOF_SECTION_HEADER, 1, peFile->Ppefile);
	}

}

void PrintSectionHeadersInfo64(PE64FILE * peFile) {
	
	printf(" SECTION HEADERS:\n");
	printf(" ----------------\n\n");

	for (int i = 0; i < peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS; i++) {
		printf("   * %.8s:\n", peFile->PEFILE_SECTION_HEADERS[i].Name);
		printf("        VirtualAddress: 0x%X\n", peFile->PEFILE_SECTION_HEADERS[i].VirtualAddress);
		printf("        VirtualSize: 0x%X\n", peFile->PEFILE_SECTION_HEADERS[i].Misc.VirtualSize);
		printf("        PointerToRawData: 0x%X\n", peFile->PEFILE_SECTION_HEADERS[i].PointerToRawData);
		printf("        SizeOfRawData: 0x%X\n", peFile->PEFILE_SECTION_HEADERS[i].SizeOfRawData);
		printf("        Characteristics: 0x%X\n\n", peFile->PEFILE_SECTION_HEADERS[i].Characteristics);
	}

}

void ParseImportDirectory64(PE64FILE * peFile) {
	
	_DWORD _import_directory_address = resolve64(
        peFile, peFile->PEFILE_IMPORT_DIRECTORY.VirtualAddress, 
        locate64(peFile, peFile->PEFILE_IMPORT_DIRECTORY.VirtualAddress)
    );
	peFile->_import_directory_count = 0;

	while (true) {
		___IMAGE_IMPORT_DESCRIPTOR tmp;
		int offset = (
            peFile->_import_directory_count * sizeof(___IMAGE_IMPORT_DESCRIPTOR)
        ) + _import_directory_address;
		fseek(peFile->Ppefile, offset, SEEK_SET);
		fread(&tmp, sizeof(___IMAGE_IMPORT_DESCRIPTOR), 1, peFile->Ppefile);

		if (tmp.Name == 0x00000000 && tmp.FirstThunk == 0x00000000) {
            // Al encontrar la entrada nula, finalizamos sin decrementar.
            peFile->_import_directory_size = peFile->_import_directory_count * sizeof(___IMAGE_IMPORT_DESCRIPTOR);
            break;
        }

		peFile->_import_directory_count++;
	}

	peFile->PEFILE_IMPORT_TABLE = malloc(sizeof(___IMAGE_IMPORT_DESCRIPTOR) * peFile->_import_directory_count);

	for (int i = 0; i < peFile->_import_directory_count; i++) {
		int offset = (i * sizeof(___IMAGE_IMPORT_DESCRIPTOR)) + _import_directory_address;
		fseek(peFile->Ppefile, offset, SEEK_SET);
		fread(&(peFile->PEFILE_IMPORT_TABLE[i]), sizeof(___IMAGE_IMPORT_DESCRIPTOR), 1, peFile->Ppefile);
	}   

}

void PrintImportTableInfo64(PE64FILE * peFile) {
	
    printf(" IMPORT TABLE:\n");
    printf(" ----------------\n\n");

    for (int i = 0; i < peFile->_import_directory_count; i++) {
        _DWORD NameAddr = resolve64(peFile, 
            peFile->PEFILE_IMPORT_TABLE[i].Name, 
            locate64(peFile, peFile->PEFILE_IMPORT_TABLE[i].Name)
        );
        int NameSize = 0;

        while (true) {
            char tmp;
            fseek(peFile->Ppefile, (NameAddr + NameSize), SEEK_SET);
            fread(&tmp, sizeof(char), 1, peFile->Ppefile);

            if (tmp == 0x00) {
                break;
            }

            NameSize++;
        }

        char* Name = malloc(NameSize + 2);
        fseek(peFile->Ppefile, NameAddr, SEEK_SET);
        fread(Name, (NameSize * sizeof(char)) + 1, 1, peFile->Ppefile);
        printf("   * %s:\n", Name);
        free(Name);

        printf("       ILT RVA: 0x%X\n", peFile->PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME__.OriginalFirstThunk);
        printf("       IAT RVA: 0x%X\n", peFile->PEFILE_IMPORT_TABLE[i].FirstThunk);

        if (peFile->PEFILE_IMPORT_TABLE[i].TimeDateStamp == 0) {
            printf("       Bound: FALSE\n");
        }
        else if (peFile->PEFILE_IMPORT_TABLE[i].TimeDateStamp == -1) {
            printf("       Bound: TRUE\n");
        }

        printf("\n");

        _DWORD ILTAddr = resolve64(peFile,
            peFile->PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME__.OriginalFirstThunk, 
            locate64(peFile,peFile->PEFILE_IMPORT_TABLE[i].DUMMYUNIONNAME__.OriginalFirstThunk));
        int entrycounter = 0;

        while (true) {

            ILT_ENTRY_64 entry;

            fseek(peFile->Ppefile, (ILTAddr + (entrycounter * sizeof(_QWORD))), SEEK_SET);
            fread(&entry, sizeof(ILT_ENTRY_64), 1, peFile->Ppefile);

            _BYTE flag = entry.ORDINAL_NAME_FLAG;
            _DWORD HintRVA = 0x0;
            _WORD ordinal = 0x0;

            if (flag == 0x0) {
                HintRVA = entry.FIELD_2.HINT_NAME_TABE;
            }
            else if (flag == 0x01) {
                ordinal = entry.FIELD_2.ORDINAL;
            }

            if (flag == 0x0 && HintRVA == 0x0 && ordinal == 0x0) {
                break;
            }

            printf("\n       Entry:\n");

            if (flag == 0x0) {
                ___IMAGE_IMPORT_BY_NAME hint;

                _DWORD HintAddr = resolve64(peFile, HintRVA, locate64(peFile, HintRVA));
                fseek(peFile->Ppefile, HintAddr, SEEK_SET);
                fread(&hint, sizeof(___IMAGE_IMPORT_BY_NAME), 1, peFile->Ppefile);
                printf("         Name: %s\n", hint.Name);
                printf("         Hint RVA: 0x%X\n", HintRVA);
                printf("         Hint: 0x%X\n", hint.Hint);
            }
            else if (flag == 1) {
                printf("         Ordinal: 0x%X\n", ordinal);
            }

            entrycounter++;
        }

        printf("\n   ----------------------\n\n");

    }

}

void ParseBaseReloc64(PE64FILE * peFile) {
    // Verificar si existe la sección de relocaciones:
    if (peFile->PEFILE_BASERELOC_DIRECTORY.VirtualAddress == 0 ||
        peFile->PEFILE_BASERELOC_DIRECTORY.Size == 0) {
        printf("No se encontró la sección de reloc.\n");
        peFile->_basreloc_directory_count = 0;
        peFile->PEFILE_BASERELOC_TABLE = NULL;
        return;
    }
    
    _DWORD _basereloc_directory_address = resolve64(peFile, 
        peFile->PEFILE_BASERELOC_DIRECTORY.VirtualAddress, 
        locate64(peFile, peFile->PEFILE_BASERELOC_DIRECTORY.VirtualAddress)
    );
    
    peFile->_basreloc_directory_count = 0;
    int _basereloc_size_counter = 0;
    
    // Recorrer la tabla de reubicaciones hasta encontrar un bloque nulo
    while (true) {
        ___IMAGE_BASE_RELOCATION tmp;
        int offset = _basereloc_directory_address + _basereloc_size_counter;
        fseek(peFile->Ppefile, offset, SEEK_SET);
        if (fread(&tmp, sizeof(___IMAGE_BASE_RELOCATION), 1, peFile->Ppefile) != 1) {
            break;  // Error o fin de archivo
        }
        
        if (tmp.VirtualAddress == 0x00000000 &&
            tmp.SizeOfBlock == 0x00000000) {
            break;
        }
        
        peFile->_basreloc_directory_count++;
        _basereloc_size_counter += tmp.SizeOfBlock;
    }
    
    // Reservar memoria para la tabla de reubicaciones
    peFile->PEFILE_BASERELOC_TABLE = malloc(
        sizeof(___IMAGE_BASE_RELOCATION) * peFile->_basreloc_directory_count
    );
    if (peFile->PEFILE_BASERELOC_TABLE == NULL) {
        printf("Error al asignar memoria para la tabla de reloc.\n");
        return;
    }
    
    _basereloc_size_counter = 0;
    for (int i = 0; i < peFile->_basreloc_directory_count; i++) {
        int offset = _basereloc_directory_address + _basereloc_size_counter;
        fseek(peFile->Ppefile, offset, SEEK_SET);
        fread(&(peFile->PEFILE_BASERELOC_TABLE[i]), sizeof(___IMAGE_BASE_RELOCATION), 1, peFile->Ppefile);
        _basereloc_size_counter += peFile->PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
    }
}


void PrintBaseRelocationsInfo64(PE64FILE *peFile) {
    if (!peFile || !peFile->PEFILE_BASERELOC_TABLE || peFile->_basreloc_directory_count == 0)
        return;
    
    printf(" BASE RELOCATIONS TABLE:\n");
    printf(" -----------------------\n");

    for (int i = 0; i < peFile->_basreloc_directory_count; i++) {
        // Usamos el RVA del bloque actual en lugar de un valor global
        _DWORD blockRVA   = peFile->PEFILE_BASERELOC_TABLE[i].VirtualAddress;
        _DWORD blockSize  = peFile->PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
        int entries       = (blockSize - sizeof(___IMAGE_BASE_RELOCATION)) / sizeof(_WORD);
        
        // Determinamos en qué sección se encuentra este bloque
        int sectionIndex = locate64(peFile, blockRVA);
        if (sectionIndex == -1) {
            printf("  [Error] No se encontró sección para RVA 0x%X\n", blockRVA);
            continue;
        }
        _DWORD blockFileOffset = resolve64(peFile, blockRVA, sectionIndex);
        
        printf("\n   Block %d: \n", i);
        printf("     Block RVA: 0x%X\n", blockRVA);
        printf("     Block size: 0x%X\n", blockSize);
        printf("     Number of entries: %d\n", entries);
        printf("     Entries:\n");

        // Las entradas comienzan justo después de la cabecera del bloque
        _DWORD entryFileOffset = blockFileOffset + sizeof(___IMAGE_BASE_RELOCATION);
        for (int j = 0; j < entries; j++) {
            _WORD value;
            int curOffset = entryFileOffset + (j * sizeof(_WORD));
            
            fseek(peFile->Ppefile, curOffset, SEEK_SET);
            if (fread(&value, sizeof(_WORD), 1, peFile->Ppefile) != 1) {
                printf("  [Error] Falló la lectura de la entrada %d del bloque %d\n", j, i);
                break;
            }
            // Extraemos el tipo (4 bits altos) y el offset (12 bits bajos)
            int relocType = (value >> 12) & 0xF;
            int relocOffset = value & 0xFFF;
            
            printf("\n       * Value: 0x%X\n", value);
            printf("         Relocation Type: 0x%X\n", relocType);
            printf("         Offset: 0x%X\n", relocOffset);
        }
        printf("\n   ----------------------\n\n");
    }
}

_DWORD align(_DWORD size, _DWORD alignment) {
    if (alignment == 0) return size;
    return (size + alignment - 1) & ~(alignment - 1);
}

void AddNewSection64(
    PE64FILE* peFile, 
    const char* newSectionName, _DWORD sizeOfRawData, 
    const void* sectionData, int sectionType) {
    // 0. Get the File and Section Alignment
    _DWORD sectionAlignment = peFile->PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment;
    _DWORD fileAlignment = peFile->PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;

    // 1.  Calculate aligned sizes
    _DWORD alignedVirtualSize = align(sizeOfRawData, sectionAlignment);
    _DWORD alignedSizeOfRawData = align(sizeOfRawData, fileAlignment);

    // 2. Calculate the position of the new section
    _DWORD lastSectionEnd = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;
    _DWORD lastRawDataEnd = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

    if (peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections > 0) {
        // Find the last section with actual raw data
        for (int i = peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections - 1; i >= 0; i--) {
            ___IMAGE_SECTION_HEADER* section = &peFile->PEFILE_SECTION_HEADERS[i];
            if (section->PointerToRawData != 0 && section->SizeOfRawData != 0) {
                lastRawDataEnd = section->PointerToRawData + section->SizeOfRawData;
                break;
            }
        }
        // Use the last section's end position for virtual address calculation
        ___IMAGE_SECTION_HEADER* lastSection = &peFile->PEFILE_SECTION_HEADERS[
            peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections - 1];
        lastSectionEnd = lastSection->VirtualAddress + lastSection->Misc.VirtualSize;
    }

    // Align the calculated values
    _DWORD newSectionVirtualAddress = align(lastSectionEnd, sectionAlignment);
    _DWORD newSectionPointerToRawData = align(lastRawDataEnd, fileAlignment);
 
    // Ensure the new section doesn't overlap with headers
     if (newSectionPointerToRawData < peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders) {
        newSectionPointerToRawData = align(peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders, fileAlignment);
     }

    // 3. Create the new section header
    ___IMAGE_SECTION_HEADER newSection;
    memset(&newSection, 0, sizeof(___IMAGE_SECTION_HEADER));
    strncpy((char*)newSection.Name, newSectionName, 8);
    newSection.Misc.VirtualSize = alignedVirtualSize;
    newSection.SizeOfRawData = align(sizeOfRawData, fileAlignment); // Ensure SizeOfRawData is aligned
    newSection.VirtualAddress = newSectionVirtualAddress;
    newSection.PointerToRawData = newSectionPointerToRawData;
    newSection.Characteristics = ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE | ___IMAGE_SCN_CNT_INITIALIZED_DATA;

    //3.5. Update the characteristics based on section type
    switch (sectionType) {
        case SECTION_TYPE_CODE:
            newSection.Characteristics |= ___IMAGE_SCN_CNT_CODE | ___IMAGE_SCN_MEM_EXECUTE;
            break;
        case SECTION_TYPE_INITIALIZED_DATA:
            newSection.Characteristics |= ___IMAGE_SCN_CNT_INITIALIZED_DATA;
            break;
        case SECTION_TYPE_UNINITIALIZED_DATA:
            newSection.Characteristics |= ___IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            break;
        default:
            //If there is no section type specified it uses the default data.
            newSection.Characteristics |= ___IMAGE_SCN_CNT_INITIALIZED_DATA;
            break;
    }

    // 4. Reallocate the section headers array
    if (peFile->PEFILE_SECTION_HEADERS == NULL) {
        peFile->PEFILE_SECTION_HEADERS = (___PIMAGE_SECTION_HEADER)malloc(sizeof(___IMAGE_SECTION_HEADER));
    } else {
        peFile->PEFILE_SECTION_HEADERS = realloc(peFile->PEFILE_SECTION_HEADERS,
                                                 sizeof(___IMAGE_SECTION_HEADER) * 
                                                 (peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections + 1));
    }
    if (peFile->PEFILE_SECTION_HEADERS == NULL) {
        fprintf(stderr, "Error reallocating section headers.\n");
        return; // Or handle the error appropriately
    }

    // 5. Add the new section to the array
    peFile->PEFILE_SECTION_HEADERS[peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections] = newSection;

    // 6. Update the NumberOfSections in the FileHeader
    peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections++;
    peFile->PEFILE_NT_HEADERS_FILE_HEADER_NUMBER_OF_SECTIONS = peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections;

    // 7. Update SizeOfImage
    peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage = align(
        newSectionVirtualAddress + alignedVirtualSize, sectionAlignment);
    peFile->PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage;
}

void WriteModifiedPEFile64(PE64FILE* peFile, const char* newFileName, char* sectionData, _DWORD sizeOfRawData) {
    FILE* newFile = fopen(newFileName, "wb");
    if (newFile == NULL) {
        printf("Error creating the new file.\n");
        return;
    }

    _DWORD fileAlignment = peFile->PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;
    _DWORD sizeOfHeaders = peFile->PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

    // 1. Write DOS Header
    fwrite(&peFile->PEFILE_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, newFile);

    // 2. Write the space between DOS Header and NT Headers (e_lfanew)
    fseek(peFile->Ppefile, sizeof(___IMAGE_DOS_HEADER), SEEK_SET);
    long dosToNtSize = peFile->PEFILE_DOS_HEADER.e_lfanew - sizeof(___IMAGE_DOS_HEADER);
    char* dosToNt = (char*)malloc(dosToNtSize);
    if (dosToNt == NULL) {
        fclose(newFile);
        return;
    }
    fread(dosToNt, dosToNtSize, 1, peFile->Ppefile);
    fwrite(dosToNt, dosToNtSize, 1, newFile);
    free(dosToNt);

    // 3. Write NT Headers (Signature, FileHeader, OptionalHeader)
    fwrite(&peFile->PEFILE_NT_HEADERS, sizeof(___IMAGE_NT_HEADERS64), 1, newFile);

    // 4. Write Section Headers
    fwrite(peFile->PEFILE_SECTION_HEADERS, sizeof(___IMAGE_SECTION_HEADER),
           peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections, newFile);

    // Pad headers to SizeOfHeaders
    _DWORD currentOffset = ftell(newFile);
    if (currentOffset < sizeOfHeaders) {
        _DWORD paddingSize = sizeOfHeaders - currentOffset;
        char* padding = (char*)calloc(1, paddingSize);
        if (!padding) {
            fclose(newFile);
            return;
        }
        fwrite(padding, 1, paddingSize, newFile);
        free(padding);
    }

    // 5. Copy Section Data
    _DWORD lastSectionEnd = 0;
    for (int i = 0; i < peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
        ___IMAGE_SECTION_HEADER* sectionHeader = &peFile->PEFILE_SECTION_HEADERS[i];
        _DWORD rawDataSize = sectionHeader->SizeOfRawData;
        _DWORD rawDataPtr = sectionHeader->PointerToRawData;

        if (rawDataPtr == 0 || rawDataSize == 0) {
            // Skip uninitialized data sections
            continue;
        }

        // Seek to the correct position in the new file
        fseek(newFile, rawDataPtr, SEEK_SET);

        if (i < peFile->PEFILE_NT_HEADERS.FileHeader.NumberOfSections - 1) {
            // Original sections
            char* sectionDataBuffer = (char*)malloc(rawDataSize);
            if (!sectionDataBuffer) {
                fclose(newFile);
                return;
            }

            fseek(peFile->Ppefile, rawDataPtr, SEEK_SET);
            fread(sectionDataBuffer, rawDataSize, 1, peFile->Ppefile);
            fwrite(sectionDataBuffer, rawDataSize, 1, newFile);
            free(sectionDataBuffer);
        } else {
            // New section
            fwrite(sectionData, sizeOfRawData, 1, newFile);
            _DWORD paddingSize = rawDataSize - sizeOfRawData;
            if (paddingSize > 0) {
                char* padding = (char*)calloc(1, paddingSize);
                if (!padding) {
                    fclose(newFile);
                    return;
                }
                fwrite(padding, 1, paddingSize, newFile);
                free(padding);
            }
        }

        lastSectionEnd = rawDataPtr + rawDataSize;
    }

    // Ensure the file size is a multiple of FileAlignment
    _DWORD currentFileSize = ftell(newFile);
    _DWORD alignedFileSize = (currentFileSize + fileAlignment - 1) & ~(fileAlignment - 1);
    _DWORD finalPaddingSize = alignedFileSize - currentFileSize;

    if (finalPaddingSize > 0) {
        char* padding = (char*)calloc(1, finalPaddingSize);
        if (!padding) {
            fclose(newFile);
            return;
        }
        fwrite(padding, 1, finalPaddingSize, newFile);
        free(padding);
    }

    fclose(newFile);
}
