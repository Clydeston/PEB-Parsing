#include <Windows.h>
#include <iostream>
#include "structs.h"

/* PROCESS ENVIORNMENT BLOCK PEB */
/* 

PEB is a structure in windows processes at a fixed address of 0x30 
x86 processes this structure is found at fs:[0x30]  segment #
x64 found at gs:[0x60]

This struct is useful as it stores very needed information about a given process
- process id 
- process name 
- loaded modules (ding ding ding ding ding)

This example will show how to get the base address of a loaded module using the peb
This is useful for av evasion as no api calls (getmodulehandle) are needed

*/

DWORD WINAPI DllAttach(HMODULE Base) {
#ifdef _DEBUG
	AllocConsole();
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);	
#endif
	_PEB* pebPtr = nullptr;
	__asm
	{
		mov eax, fs:[0x30]		
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

		const wchar_t* moduleName = L"KERNEL32.DLL";

		if (wcswcs(ldrDataEntry->FullDllName.Buffer, moduleName))
		{
			printf("Found kernel32.dll base: %p \n", ldrDataEntry->DllBase);
		}
	}

	printf("[+] Finished iterating loaded modules");
	while (!(GetAsyncKeyState(VK_DELETE) & 1))
	{		
		/*
		MAIN LOOP HERE
		*/
		Sleep(1);
	}
	FreeLibraryAndExitThread(Base, 0);

}

DWORD WINAPI DllDetach() {
#ifdef _DEBUG
	fclose((FILE*)stdin);
	fclose((FILE*)stdout);

	HWND hw_ConsoleHwnd = GetConsoleWindow();
	FreeConsole();
	PostMessageW(hw_ConsoleHwnd, WM_CLOSE, 0, 0);
#endif

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DllAttach, hModule, NULL, NULL);
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{

		DllDetach();
	}
	return TRUE;	
}

