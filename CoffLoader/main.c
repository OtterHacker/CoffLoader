#define _CRT_SECURE_NO_WARNINGS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#include "Coff.h"
#include <stdio.h>
#include <stdlib.h>
#include "External.h"


void readFile(char* filename, char** string) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Cannot open the file\n");
        return;
    }
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    *string = (char*)malloc(fsize + 1);
    if (!*string) {
        printf("Cannot allocate string buffer");
        return;
    }
    fread(*string, fsize, 1, f);
    fclose(f);

    (*string)[fsize] = 0;
}

int main(int argc, char **argv){
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    char* string;
    readFile("C:\\no_scan\\CoffLoader\\dir.x64.o", &string);
    if (!string) {
        printf("Cannot open the file\n");
        exit(-1);
    }

    short subdir = 1;
    Arg arg[2] = {
        {
            .value = &L"C:\\no_scan\\",
            .size = (wcslen(L"C:\\no_scan\\") + 1) * sizeof(wchar_t),
            .includeSize = TRUE
        },
        {
            .value = &subdir,
            .size = sizeof(short),
            .includeSize = FALSE,
        },
    };

    void* argumentsString = NULL;
    size_t argumentsSize;
    PackData(arg, 2, &argumentsString, &argumentsSize);

    link((void*)string, "go", argumentsString, argumentsSize);

    char* outdata = NULL;
    int outdataSize = 0;
    outdata = BeaconGetOutputData(&outdataSize);
    if (outdata != NULL) {
    
        printf("Outdata Below:\n\n%s\n", outdata);
    }
    free(string);
    free(outdata);
    free(argumentsString);
    _CrtDumpMemoryLeaks();
    return 0;
}