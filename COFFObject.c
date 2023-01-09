// Compile : cl.exe /c /GS- .\CoffLoader\test.c /FoCOFFObject.obj

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
WINBASEAPI int __cdecl MSVCRT$printf(const char* test, ...);
WINBASEAPI int User32$MessageBoxA(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType);

const char* TestGlobalString = "This is a global string";
/* Can't do stuff like "int testvalue;" in a coff file, because it assumes that
 * the symbol is like any function, so you would need to allocate a section of bss
 * (without knowing the size of it), and then resolve the symbol to that. So safer
 * to just not support that */
int testvalue = 1;
char plop[4];
char plip[4];
int poom;
int test(void) {
    int a = 5;
    int b = 6;
    plop[0] = 'a';
    plop[1] = 'b';
    plop[2] = 'c';
    plop[3] = 0x0;
    plip[0] = 'd';
    plip[1] = 'e';
    plip[2] = 'f';
    plip[3] = 0x0;
    poom = 5;
    MSVCRT$printf("Test String from test\n");
    MSVCRT$printf("Ahahahahaha ! It works ! \n");
    testvalue += 1;
    testvalue += 3;
    int c = b + testvalue;
    c += a;
    MSVCRT$printf("Global variable : %s \n", plop);
    MSVCRT$printf("Global variable : %s \n", plip);
    MSVCRT$printf("Global variable : %d \n", poom);
    User32$MessageBoxA(NULL, "Wow ! It works !", TestGlobalString, NULL);
    
    return 0;
}

//int test2(void) {
//    MSVCRT$printf("Test String from test2\n");
//    MSVCRT$printf("Ahahahahaha ! It works on test2 too ! ");
//    return 0;
//}


//void go(char* args, unsigned long alen) {
//    MSVCRT$printf("Ahahahahaha ! It works ! ");
//    //MSVCRT$printf("Test Value: %d\n", testvalue);
//    (void)test();
//    //MSVCRT$printf("Test ValueBack: %d\n", testvalue);
//    (void)test2();
//}