// Compile : cl.exe /c /GS- .\CoffLoader\test.c /FoCOFFObject.obj

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>
#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT int __cdecl MSVCRT$printf(const char* test, ...);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy(char *strDestination, const char *strSource);
DECLSPEC_IMPORT int User32$MessageBoxA(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType);
DECLSPEC_IMPORT BOOL Advapi32$GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);

const char* TestGlobalString = "This is a global string";
/* Can't do stuff like "int testvalue;" in a coff file, because it assumes that
 * the symbol is like any function, so you would need to allocate a section of bss
 * (without knowing the size of it), and then resolve the symbol to that. So safer
 * to just not support that */
int testvalue = 1;
char plop[11];
char plip[11];
int a;
int poom;
int salut;

typedef struct _blah{
    int a;
    char c[10];
} blah;

int test(void) {
    BeaconPrintf(1, "This GlobalString from beacon internal function \"%s\"\n", TestGlobalString);
    a = 0xFFFFFFFD;
    int b = 6;
    salut = 0xFFFFFFFF;
    plop[0] = 'a';
    plop[1] = 'b';
    plop[2] = 'c';
    plop[3] = 'd';
    plop[4] = 'e';
    plop[5] = 'f';
    plop[6] = 'g';
    plop[7] = 'h';
    plop[8] = 'i';
    plop[9] = 'j';
    plop[10] = 0x0;
    plip[0] = 'k';
    plip[1] = 'l';
    plip[2] = 'm';
    plip[3] = 'n';
    plip[4] = 'o';
    plip[5] = 'p';
    plip[6] = 'q';
    plip[7] = 'r';
    plip[8] = 's';
    plip[9] = 't';
    plip[10] = 0x0;

    poom = 0xFFFFFFFE;

    MSVCRT$printf("TEST VALUE : %d\n", a);
    MSVCRT$printf("TEST VALUE : %d\n", b);
    MSVCRT$printf("TEST VALUE : %d\n", salut);

    MSVCRT$printf("Test String from test\n");
    MSVCRT$printf("Ahahahahaha ! It works ! \n");
    MSVCRT$printf("Ahahahahaha ! It works ! \n");
    MSVCRT$printf("Ahahahahaha ! It works ! \n");
    testvalue += 1;
    testvalue += 3;
    int c = b + testvalue;
    c += a;
    MSVCRT$printf("Global variable : %s \n", plop);
    MSVCRT$printf("Global variable : %s \n", plip);
    MSVCRT$printf("Global variable : %d \n", poom);
    MSVCRT$printf("Global variable : %d \n", a);
    //User32$MessageBoxA(NULL, "Wow ! It works !\n", TestGlobalString, NULL);
    (void)test2();

    blah blahTest;
    blahTest.a = 5;
    MSVCRT$strcpy(blahTest.c, "salut");

    MSVCRT$printf("Structure : %d \n", blahTest.a);
    MSVCRT$printf("Structure : %s \n", blahTest.c);
    return 0;
}

int test2(void) {
    MSVCRT$printf("Test String from test2\n");
    MSVCRT$printf("Ahahahahaha ! It works on test2 too !\n");
    return 0;
}
void go(char* args, unsigned long alen) {
    (void)test();
    DWORD dwRet;
    long unsigned int buffsize=255;
    char username[255];
    Advapi32$GetUserNameA(username, &buffsize);
    BeaconPrintf(CALLBACK_OUTPUT, "Username : %s\n", username); 
}