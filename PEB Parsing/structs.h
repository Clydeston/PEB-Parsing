#pragma once
#include <Windows.h>
#include <SubAuth.h>

/*
The structure of the PEB
At 0x0c of the structure we have the ldr property
LDR is a struct (_PEB_LDR_DATA) containing a doubly linked list => InMemoryOrderModuleList

This struct is the head of this doubly linked list
Each list item is a ptr to LDR_DATA_TABLE_ENTRY struct

*/

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
	// ^ head of doubly linked list 
	// points to LIST_ENTRY struct in LDR_DATA_TABLE_ENTRY struct 
	// rather than base of struct
	// so remember to go back to the base of struct via 
	// ldr_table_entry_ptr - sizeof(list_entry)
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	void* /*PRTL_USER_PROCESS_PARAMETERS*/ ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	void* /*PPS_POST_PROCESS_INIT_ROUTINE*/ PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;
