#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma once
#ifndef EXTERNAL_H
#define EXTERNAL_H
#include <windows.h>
#include "stdint.h"

extern unsigned char* internalFunctions[29][2];

typedef struct _Arg {
    void* value;
    size_t size;
    BOOL includeSize;
} Arg;


typedef struct {
    char* original; /* the original buffer [so we can free it] */
    char* buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

typedef struct {
    char* original; /* the original buffer [so we can free it] */
    char* buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;


void PackData(Arg* args, size_t numberOfArgs, char** output, size_t* size);
void BeaconDataParse(datap* parser, char* buffer, int size);
int BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

void BeaconFormatAlloc(formatp* format, int maxsz);
void BeaconFormatReset(formatp* format);
void BeaconFormatFree(formatp* format);
void BeaconFormatAppend(formatp* format, char* text, int len);
void BeaconFormatPrintf(formatp* format, char* fmt, ...);
char* BeaconFormatToString(formatp* format, int* size);
void BeaconFormatInt(formatp* format, int value);

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20


void BeaconPrintf(int type, char* fmt, ...);
void BeaconOutput(int type, char* data, int len);

/* Token Functions */
BOOL BeaconUseToken(HANDLE token);
void BeaconRevertToken();
BOOL BeaconIsAdmin();

/* Spawn+Inject Functions */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo);
void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

/* Utility Functions */
BOOL toWideChar(char* src, wchar_t* dst, int max);
uint32_t swap_endianess(uint32_t indata);

char* BeaconGetOutputData(int* outsize);

#endif