#include <Windows.h>
#include <iostream>
#include "modules.h"
#include "exports.h"

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

// TODO FIX RUN TIME CHECK FAILURE #0
typedef void*(WINAPI* GetProcAddressProto)(HMODULE, LPCSTR);

typedef void* (__stdcall* tGetProcAddress)(void*, char*);

DWORD WINAPI DllAttach(HMODULE Base) {
#ifdef _DEBUG
	AllocConsole();
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);	
#endif
	
	char* kernel32Module = GetModule(L"KERNEL32.DLL");
	char* user32Module = GetModule(L"USER32.DLL");
	char* getProcAddressPtr = GetExportedFunction((char*)"GetProcAddress", kernel32Module);
		
	printf("GetProcAddress ptr -> %p\n", getProcAddressPtr);	

	GetProcAddressProto myGetProcAddress = (GetProcAddressProto)GetExportedFunction((char*)"GetProcAddress", kernel32Module);;
	printf("GetProcAddres address my: %p", myGetProcAddress);
	// cannot get exported function for some reason?? 
	myGetProcAddress((HMODULE)kernel32Module, "GetProcAddress");

	//tGetProcAddress getProcAddress = (tGetProcAddress)GetExportedFunction((char*)"GetProcAddress", kernel32Module);
	//printf("GetProcAddress typedef ptr -> %p\n", getProcAddress);

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

