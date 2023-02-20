#pragma once
#include <Windows.h>
#include "structs.h"

/// <summary>
/// Case sensitive
/// </summary>
/// <param name="moduleName"></param>
/// <returns></returns>
char* GetModule(const wchar_t* moduleName)
{
	_PEB* pebPtr = nullptr;
	__asm
	{
		mov eax, fs: [0x30]
		mov pebPtr, eax
	}
	printf("PEB Pointer: %p \n", pebPtr);

	if (!pebPtr)
	{
		printf("[+] Fucked it");
	}
	// ptr to PEB_LDR_DATA struct which contains doubly linked list of all modules
	PEB_LDR_DATA* peb_ldr_data = pebPtr->Ldr;
	// first item of doublu linked list
	LIST_ENTRY* list_head = &(peb_ldr_data->InMemoryOrderModuleList);
	// ptr to current module being interated
	LIST_ENTRY* list_entry;
	// the list is circular so instead of null value iteration stops when the list has completed one full loop
	for (list_entry = list_head->Flink; list_entry != list_head; list_entry = list_entry->Flink)
	{
		// LIST_ENTRY struct points to the InMemoryOrderLinks property 
		// this means to get the LDR_DATA_TABLE_ENTRY for every module 
		// we need to account for that by going back to 0x0 of the struct
		LDR_DATA_TABLE_ENTRY* ldrDataEntry = (LDR_DATA_TABLE_ENTRY*)((char*)list_entry - sizeof(LIST_ENTRY));

		printf("Module: %ls Loaded \n", ldrDataEntry->FullDllName.Buffer);

		if (wcswcs(ldrDataEntry->FullDllName.Buffer, moduleName))
		{			
			return (char*)ldrDataEntry->DllBase;
			break;
		}
	}
}