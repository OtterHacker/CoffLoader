#define _CRT_SECURE_NO_WARNINGS
#include "Coff.h"
#include "External.h"

void link(void* data, char* entryPoint, char* argumentdata, unsigned long argumentsize) {
	size_t gotMax = 0x0;
	size_t bssMax = 0x0;
	BssEntry* bssEntry = NULL;
	GotEntry* gotEntry = NULL;
	void* got = NULL;
	void* bss = NULL;
	size_t gotSize = 0;
	size_t bssSize = 0;
	size_t bssOffset = 0;
	void** sectionsAddress = NULL;
	void* textSectionAddress = NULL;
	uint64_t textSectionSize = -1;

	CoffHeader *coffHeader = (CoffHeader *)data;
	DEBUG("Parsing header\n");
	DEBUG("\tMachine 0x%X\n", coffHeader->machine);
	DEBUG("\tNumber of sections: %d\n", coffHeader->numberOfSections);
	DEBUG("\tTimeDateStamp : %d\n", coffHeader->timeDateStamp);
	DEBUG("\tPointerToSymbolTable : 0x%X\n", coffHeader->pointerToSymbolTable);
	DEBUG("\tNumberOfSymbols: %d\n", coffHeader->numberOfSymbols);
	DEBUG("\tOptionalHeaderSize: %d\n", coffHeader->sizeOfOptionalHeader);
	DEBUG("\tCharacteristics: %d\n", coffHeader->characteristics);
	DEBUG("\n\n");

	sectionsAddress = (void **)calloc(coffHeader->numberOfSections, sizeof(void*));
	if (!sectionsAddress) {
		DEBUG("Cannot allocate sections adress\n");
		goto cleanMemory;
	}
	
	// Allocate sections memory
	for (uint32_t i = 0; i < coffHeader->numberOfSections; i++) {
		CoffSection* section = (CoffSection *)(void *)((uint64_t)data + HEADER_SIZE + SECTION_SIZE * (uint64_t)i);
		if (section->sizeOfRawAddress == 0) {
			continue;
		}
		sectionsAddress[i] = VirtualAlloc(
			NULL, 
			section->sizeOfRawAddress, 
			MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, 
			PAGE_READWRITE
		);

		if (!sectionsAddress[i]) {
			DEBUG("Cannot allocate section memory");
			goto cleanMemory;
		}

		if (section->name[0] != 0x0 && strncmp(section->name, ".text", 5) == 0) {
			textSectionAddress = sectionsAddress[i];
			textSectionSize = section->sizeOfRawAddress;
		}

		CopyMemory(sectionsAddress[i], (void*)((uint64_t)data + section->pointerToRawData), section->sizeOfRawAddress);

		DEBUG("Allocating section %d", i);
		DEBUG("\tName : %s\n", section->name);
		DEBUG("\tVirtual size : 0x%X\n", section->virtualSize);
		DEBUG("\tVirtual address : 0x%X\n", section->virtualAddress);
		DEBUG("\tSize of raw address : 0x%X\n", section->sizeOfRawAddress);
		DEBUG("\tPointer to raw data : 0x%X\n", section->pointerToRawData);
		DEBUG("\tPointer to relocations : 0x%X\n", section->pointerToRelocations);
		DEBUG("\tPointer to linenumber : 0x%X\n", section->pointerToLinenumber);
		DEBUG("\tNumber of relocations : %d\n", section->numberOfRelocations);
		DEBUG("\tNumber of linenumber : %d\n", section->numberOfLinenumber);
		DEBUG("\tCharacteristics : 0x%X\n", section->characteristics);
		DEBUG("\tAllocation address : 0x%p\n", sectionsAddress[i]);
		DEBUG("\n\n");

	}

	if (!textSectionAddress) {
		DEBUG(".text section not found\n");
		goto cleanMemory;
	}

	CoffSymbol* symbols = (CoffSymbol*)((uint64_t)data + coffHeader->pointerToSymbolTable);
	for (uint32_t i = 0; i < coffHeader->numberOfSymbols; i++) {
		CoffSymbol* coffSymbol = (CoffSymbol*)((uint64_t)symbols + (uint64_t)i * SYMBOL_SIZE);
		if (coffSymbol->storageClass == IMAGE_SYM_CLASS_EXTERNAL && coffSymbol->sectionNumber == 0x0) {
			char* symbolName = coffSymbol->first.name;
			if (symbolName[0] == 0x0) {
				uint64_t nameOffset = coffSymbol->first.value[1];
				symbolName = (char*)((uint64_t)symbols + (uint64_t)coffHeader->numberOfSymbols * SYMBOL_SIZE + nameOffset);
			}
			void* functionAddress = loadExternalFunction(symbolName);
			if (functionAddress != NULL) {
				if (gotSize == gotMax) {
					void* tmp = gotEntry;
					gotEntry = (GotEntry *)realloc(tmp, (gotMax + 0x10) * sizeof(GotEntry));
					if (!gotEntry) {
						DEBUG("Cannot reallocate got array\n");
						goto cleanMemory;
					}
					gotMax += 0x10;
				}
				gotEntry[gotSize] = (GotEntry){.function = functionAddress, .gotOffset = (uint64_t)gotSize * 0x08, .symbol = coffSymbol };
				gotSize += 1;
			}
			else {
				if (bssSize == bssMax) {
					void* tmp = bssEntry;
					bssEntry = (BssEntry *)realloc(tmp, (bssMax + 0x10) * sizeof(BssEntry));
					if (!bssEntry) {
						DEBUG("Cannot reallocate bss array\n");
						goto cleanMemory;
					}
					bssMax += 0x10;
				}
				bssEntry[bssSize] = (BssEntry){ .symbol = coffSymbol, .bssOffset = bssOffset };
				bssOffset += coffSymbol->value;
				bssSize += 1;
			}

		}
	}

	if (gotSize > 0) {
		void* tmp = gotEntry;
		gotEntry = (GotEntry*)realloc(tmp, gotSize * sizeof(GotEntry));
		if (!gotEntry) {
			DEBUG("Cannot reallocate got entry\n");
			goto cleanMemory;
		}
	}
	if (bssSize > 0) {
		void* tmp = bssEntry;
		bssEntry = (BssEntry*)realloc(tmp, (bssSize) * sizeof(BssEntry));
		if (!bssEntry) {
			DEBUG("Cannot reallocate bss entry\n");
			goto cleanMemory;
		}
	}

	// Allocate special sections for external functions
	
	got = VirtualAlloc(NULL, (uint64_t)gotSize * 0x08, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	if (!got && gotSize != 0) {
		DEBUG("Cannot allocate GOT\n");
		goto cleanMemory;
	}
	DEBUG(".got allocation address : 0x%p\n", got);
	

	// Allocate special section for unintialized variable
	bss = VirtualAlloc(NULL, bssOffset, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	if (!bss && bssOffset != 0) {
		DEBUG("Cannot allocation BSS section\n");
		goto cleanMemory;
	}

	DEBUG(".bss Allocation address : 0x%p\n", bss);

	// Start parsing symbols. The symbols are processed section by section
	// The relocations are written in memory on-the-fly.
	for (uint32_t i = 0; i < coffHeader->numberOfSections; i++) {
		CoffSection* section = (CoffSection*)((uint64_t)data + HEADER_SIZE + (uint64_t)i * SECTION_SIZE);
		DEBUG("Making relocation of section %d\n", i);

		// Parse all relocation of the section
		for (uint32_t j = 0; j < section->numberOfRelocations; j++) {
			void* source;
			size_t destSize;
			uint64_t bssAddress = -1;

			CoffReloc* reloc = (CoffReloc*)((uint64_t)data + section->pointerToRelocations + RELOC_SIZE * (uint64_t)j);
			CoffSymbol* coffSymbol = (CoffSymbol*)((uint64_t)symbols + (uint64_t)reloc->symbolTableIndex * SYMBOL_SIZE);

			char* symbolName = coffSymbol->first.name;
			if (symbolName[0] == 0x0) {
				uint64_t nameOffset = coffSymbol->first.value[1];
				symbolName = (char*)((uint64_t)symbols + (uint64_t)coffHeader->numberOfSymbols * SYMBOL_SIZE + nameOffset);
			}

			DEBUG("\tOffset : 0x%llX\n", (uint64_t)(coffSymbol)-(uint64_t)(data));
			DEBUG("\tName : %s\n", symbolName);
			DEBUG("\tSection number : %d\n", coffSymbol->sectionNumber);
			DEBUG("\tType : %d\n", coffSymbol->type);
			DEBUG("\tStorage class : %d\n", coffSymbol->storageClass);
			DEBUG("\tNumber of AuxSymbols : %d\n", coffSymbol->numberOfAuxSymbols);
			DEBUG("\tVirtual Address : 0x%X\n", reloc->virtualAddress);

			void* symbolRefAddress = (void*)((uint64_t)sectionsAddress[i] + reloc->virtualAddress);

			// Process function and unitialized variables
			if (coffSymbol->storageClass == IMAGE_SYM_CLASS_EXTERNAL && coffSymbol->sectionNumber == 0x0) {
				DEBUG("\tUnusual symbol detected\n");
				void* gotAddress = NULL;
				void* functionAddress = NULL;
				for (uint32_t k = 0; k < gotSize; k++) {
					if (gotEntry[k].symbol == coffSymbol) {
						gotAddress = (void*)((uint64_t)got + gotEntry[k].gotOffset);
						functionAddress = gotEntry[k].function;
						break;
					}
				}
				if (functionAddress != NULL && reloc->type == IMAGE_REL_AMD64_REL32) {
					if (!gotAddress) {
						goto cleanMemory;
					}
					// Copy the function address to the GOT table
					CopyMemory(gotAddress, &functionAddress, sizeof(uint64_t));
					// Compute the relative address to write on the relocation
					uint32_t relativeAddress = (uint32_t)((uint64_t)gotAddress - ((uint64_t)symbolRefAddress + 4));
					source = &relativeAddress;
					destSize = sizeof(uint32_t);
					DEBUG("\t\tSymbol relative address : 0x%X\n", relativeAddress);
					DEBUG("\t\tSymbol address : 0x%p\n", sectionsAddress[coffSymbol->sectionNumber - 1]);

					DEBUG("\n\n");
					// Nothing more to do, can just copy the address in memory
					goto copyMem;
				}	
				else {
					// Create the entry in the .bss section for uninitialized variables
					// The generated address must be replaced in the relocation according
					// to the relocation type.
					for (uint32_t k = 0; k < bssSize; k++) {
						if ((uint64_t)coffSymbol == (uint64_t)bssEntry[k].symbol) {
							bssAddress = (uint64_t)bss + bssEntry[k].bssOffset;
							break;
						}
					}

					uint32_t relativeAddress = (uint32_t)(bssAddress - ((uint64_t)symbolRefAddress + 3));
				}
			}


			if (reloc->type == IMAGE_REL_AMD64_ADDR64) {
				uint64_t segmentOffset = 0;
				uint64_t symbolDefAddress = 0;
				if (bssAddress != -1) {
					symbolDefAddress = bssAddress - ((uint64_t)symbolRefAddress + 4);
				}
				else {
					segmentOffset = getOffset64(symbolRefAddress, reloc, coffSymbol);
					symbolDefAddress = segmentOffset + (uint64_t)sectionsAddress[coffSymbol->sectionNumber - 1];
				}
				
				source = &symbolDefAddress;
				destSize = sizeof(uint64_t);
				DEBUG("\t\tSegment offset : 0x%llX\n", segmentOffset);
				DEBUG("\t\tSymbol relative address : 0x%llX\n", symbolDefAddress);
				DEBUG("\t\tSymbol address : 0x%p\n", sectionsAddress[coffSymbol->sectionNumber - 1]);
			}
			else if(reloc->type == IMAGE_REL_AMD64_ADDR32NB) {
				uint32_t relSymbolDefAddress = 0;
				uint32_t segmentOffset = 0;
				if (bssAddress != -1) {
					relSymbolDefAddress = (uint32_t)(bssAddress - ((uint64_t)symbolRefAddress + 4));
				}
				else {
					segmentOffset = getOffset32(symbolRefAddress, reloc, coffSymbol);
					relSymbolDefAddress = (uint32_t)(((uint64_t)sectionsAddress[coffSymbol->sectionNumber - 1]) - ((uint64_t)symbolRefAddress + 4));

					if (relSymbolDefAddress + segmentOffset > 0xFFFFFFFF) {
						DEBUG("Relocation to long, just skipping\n");
						continue;
					}

					relSymbolDefAddress += segmentOffset;
				}

				source = &relSymbolDefAddress;
				destSize = sizeof(uint32_t);

				DEBUG("\t\tSegment offset : 0x%X\n", segmentOffset);
				DEBUG("\t\tRelative address : 0x%X\n", relSymbolDefAddress);
			}

			else if (IMAGE_REL_AMD64_REL32 <= reloc->type && reloc->type <= IMAGE_REL_AMD64_REL32_5) {
				uint32_t relSymbolDefAddress = 0;
				uint32_t segmentOffset = 0;

				// The (reloc->type - 4) offset is used to generalize the reloc type
				// whose address is given as relative to byte distance x from the reloc.
				// Thus no need to rewrite the code for each of these types.
				if (bssAddress != -1) {
					relSymbolDefAddress = (uint32_t)((uint64_t)bssAddress - (uint64_t)(reloc->type - 4) - ((uint64_t)symbolRefAddress + 4));
				}
				else {
					segmentOffset = getOffset32(symbolRefAddress, reloc, coffSymbol);
					relSymbolDefAddress = (uint32_t)(((uint64_t)sectionsAddress[coffSymbol->sectionNumber - 1]) - (uint64_t)(reloc->type - 4) - ((uint64_t)symbolRefAddress + 4));

					if (relSymbolDefAddress > 0xFFFFFFFF) {
						DEBUG("Relocation to long, just skipping\n");
						continue;
					}

					relSymbolDefAddress += segmentOffset;
				}

				source = &relSymbolDefAddress;
				destSize = sizeof(uint32_t);
				DEBUG("\t\tSegment offset : 0x%X\n", segmentOffset);
				DEBUG("\t\tRelative address : 0x%X\n", relSymbolDefAddress);
			}

			else {
				DEBUG("Relocation type %d not supported yet...\n", reloc->type);
				goto cleanMemory;
			}
			copyMem:
			CopyMemory(symbolRefAddress, source, destSize);
			DEBUG("\n\n");
		}
	}

	// Make the .text section executable
	DWORD old;
	VirtualProtect(
		textSectionAddress,
		textSectionSize,
		PAGE_EXECUTE_READ,
		&old
	);

	DEBUG("Set text section as RX\n");
	run(entryPoint, argumentdata, argumentsize, data, coffHeader, sectionsAddress);
	cleanMemory:
	clean(sectionsAddress, data, got, bss, gotEntry, bssEntry, gotSize, bssSize);
	free(gotEntry);
	free(bssEntry);
	free(sectionsAddress);
	
	
}

void clean(void** sectionsAddress, void* data, void* gotAddress, void* bssAddress, GotEntry* gotEntry, BssEntry* bssEntry, size_t gotSize, size_t bssSize) {
	DEBUG("Clean up allocated sections\n");
	CoffHeader* coffHeader = (CoffHeader*)data;

	for (uint32_t i = 0; i < coffHeader->numberOfSections; i++) {
		CoffSection* section = (CoffSection*)((uint64_t)data + HEADER_SIZE + (uint64_t)i * SECTION_SIZE);
		VirtualFree(sectionsAddress[i], 0, MEM_RELEASE);
	}

	DEBUG("Clean up GOT section\n");
	if (gotAddress) {
		VirtualFree(gotAddress, 0, MEM_RELEASE);
	}

	DEBUG("Clean up BSS section\n");
	if (bssAddress) {
		VirtualFree(bssAddress, 0, MEM_RELEASE);
	}
}

void run(char* functionName, char* argumentdata, unsigned long argumentsize, void* data, CoffHeader* coffHeader, void** sectionsAddress) {
	// Find the entry point and run it as a shellcode
	CoffSymbol* symbols = (CoffSymbol*)((uint64_t)data + coffHeader->pointerToSymbolTable);
	for (uint32_t i = 0; i < coffHeader->numberOfSymbols; i++) {
		CoffSymbol* coffSymbol = (CoffSymbol*)((uint64_t)symbols + (uint64_t)i * SYMBOL_SIZE);

		int find = 0;
		char* symbolName = NULL;
		if (coffSymbol->first.name[0] != 0x0) {
			symbolName = coffSymbol->first.name;
		}
		else {
			uint64_t nameOffset = coffSymbol->first.value[1];
			symbolName = (char*)((uint64_t)symbols + (uint64_t)coffHeader->numberOfSymbols * SYMBOL_SIZE + nameOffset);
		}
		if (strcmp(symbolName, functionName) == 0) {
			void(*foo)(char* in, unsigned long datalen);
			foo = (void(*)(char*, unsigned long))((char*)sectionsAddress[coffSymbol->sectionNumber - 1] + coffSymbol->value);
			DEBUG("\n============================\n\n");
			foo(argumentdata, argumentsize);
			DEBUG("\n============================\n\n");
		}
	}
}

void* loadExternalFunction(char* symbolName) {
	void* function = NULL;
	HMODULE library = NULL;
	char* symbolString = (char*)calloc(strlen(symbolName) + 1, sizeof(char));
	if (!symbolString) {
		DEBUG("Cannot allocate symbol string\n");
		return NULL;
	}
	strcpy(symbolString, symbolName);
	void *save = symbolString;
	if (strncmp(symbolString, "__imp_", 6) == 0) {
		symbolString += 6;
		char* libraryName = strtok(symbolString, "$");
		char* functionName = strtok(NULL, "@");
		if (functionName == NULL) {
			// That's an internal beacon function
			//function = (void*)GetProcAddress(GetModuleHandle(NULL), symbolString);
			for (uint32_t i = 0; i < 29; i++) {
				if (internalFunctions[i][0] != NULL) {
					if (strcmp((char*)internalFunctions[i][0], libraryName) == 0) {
						function = internalFunctions[i][1];
						break;
					}
				}
			}
			functionName = libraryName;
			libraryName[0] = '\0';			
		}
		else {
			library = LoadLibraryA(libraryName);
			if (!library) {
				DEBUG("Cannot load library %s\n", libraryName);
				free(save);
				return NULL;
			}
			function = (void*)GetProcAddress(library, functionName);
		}


		DEBUG("\tUnknown symbol is a function\n");
		DEBUG("\t\tName : %s\n", functionName);
		DEBUG("\t\tLibrary : %s\n", libraryName);
		DEBUG("\t\tModule address : 0x%p\n", library);
		DEBUG("\t\tProcAddress : 0x%p\n", function);
		free(save);
		return function;
		
	}
	free(save);
	return NULL;
}

uint32_t getOffset32(void *symbolReferenceAddress, CoffReloc* reloc, CoffSymbol* symbol) {
	if ((symbol->storageClass == IMAGE_SYM_CLASS_STATIC && symbol->value != 0) || (symbol->storageClass == IMAGE_SYM_CLASS_EXTERNAL && symbol->sectionNumber != 0x0)) {
		// With static class symbol, the offset is given through the symbol->value (if not 0)
		// and not in the segment symbol address last bytee
		return symbol->value;
	}
	else {
		// For standard symbol, the offset is given as the last byte of the
		// value pointed by the symbol reference address in the section.
		uint32_t segmentOffset = 0;
		CopyMemory(&segmentOffset, symbolReferenceAddress, sizeof(uint32_t));
		return segmentOffset;
	}
}

uint64_t getOffset64(void* symbolReferenceAddress, CoffReloc* reloc, CoffSymbol* symbol) {
	if ((symbol->storageClass == IMAGE_SYM_CLASS_STATIC && symbol->value != 0) || (symbol->storageClass == IMAGE_SYM_CLASS_EXTERNAL && symbol->sectionNumber != 0x0)) {
		// With static class symbol, the offset is given through the symbol->value (if not 0)
		// and not in the segment symbol address last byte
		return symbol->value;
	}
	else {
		// For standard symbol, the offset is given as the last byte of the
		// value pointed by the symbol reference address in the section.
		uint64_t segmentOffset = 0;
		CopyMemory(&segmentOffset, symbolReferenceAddress, sizeof(uint64_t));
		return segmentOffset;
	}
}