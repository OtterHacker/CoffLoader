#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma once
#ifndef COFF_H
#define COFF_H

#ifdef _DEBUG
#define DEBUG(x, ...) //printf(x, ##__VA_ARGS__)
#else
#define DEBUG(x, ...)
#endif

#define HEADER_SIZE 0x14
#define SECTION_SIZE 0x28
#define SYMBOL_SIZE 0x12
#define RELOC_SIZE 0x0A
#define BSS_SIZE 0x800
#define GOT_SIZE 0x800

#include <stdint.h>
#include <windows.h>

typedef struct _CoffHeader {
	uint16_t	machine;
	uint16_t	numberOfSections;
	uint32_t	timeDateStamp;
	uint32_t	pointerToSymbolTable;
	uint32_t	numberOfSymbols;
	uint16_t	sizeOfOptionalHeader;
	uint16_t	characteristics;
} CoffHeader;

typedef struct _CoffSection {
	char		name[8];
	uint32_t	virtualSize;
	uint32_t	virtualAddress;
	uint32_t	sizeOfRawAddress;
	uint32_t	pointerToRawData;
	uint32_t	pointerToRelocations;
	uint32_t	pointerToLinenumber;
	uint16_t	numberOfRelocations;
	uint16_t	numberOfLinenumber;
	uint32_t	characteristics;
} CoffSection;

typedef struct _CoffReloc {
	uint32_t	virtualAddress;
	uint32_t	symbolTableIndex;
	uint16_t	type;
} CoffReloc;

typedef struct _CoffSymbol {
	union {
		char		name[8];
		uint32_t	value[2];
	} first;
	uint32_t	value;
	uint16_t	sectionNumber;
	uint16_t	type;
	uint8_t		storageClass;
	uint8_t		numberOfAuxSymbols;

} CoffSymbol;

typedef struct _BssEntry {
	void* symbol;
	uint64_t bssOffset;
} BssEntry;

typedef struct _GotEntry {
	void* function;
	uint64_t gotOffset;
	void* symbol;
} GotEntry;


void link(void* coffFile, char* entryPoint, char* argumentdata, unsigned long argumentsize);
void run(char* functionName, char* argumentdata, unsigned long argumentsize, void* data, CoffHeader* coffHeader, void** sectionsAddress);
void* loadExternalFunction(char* symbolName);
uint32_t getOffset32(void *symbolReferenceAddress, CoffReloc* reloc, CoffSymbol* symbol);
uint64_t getOffset64(void *symbolReferenceAddress, CoffReloc* reloc, CoffSymbol* symbol);
void clean(void** sectionsAddress, void* data, void* gotAddress, void* bssAddress, GotEntry* gotEntry, BssEntry* bssEntry, size_t gotSize, size_t bssSize);


#endif;
