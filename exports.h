#pragma once
#include <Windows.h>
#include <iostream>

/*
* https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
* https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/
* https://resources.infosecinstitute.com/topic/the-export-directory/
* https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/
* https://0xrick.github.io/win-internals/pe4/
* https://nutcrackerssecurity.github.io/PE-file.html
* https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb
Export directory table 

Export directory table is a section in PE file formats which stores
the addresses of all the exported functions from that module

The export table is located inside the optional header section of the pe file
To find a function within the export table, you must use an ordinal number as an index

Essentially the code below is the equivalent of getprocaddress - just without using this api call

PE file structure is as follows 

DOS HEADER - _IMAGE_DOS_HEADER
DOS STUB 
NT_HEADER - _IMAGE_NT_HEADERS 

Two key properties of the dos_header struct are the e_magic and e_lfanew
e_magic = magic number MZ 0x5A4D
e_lfanew = pointer to exectuable header which is image_nt_headers

The top two headers dos header and dos stub are only required for programs to run in ms dos
However those two properties from those headers are used by modern programs to compile


*/

char* GetExportedFunction(char* exportedFunctionName, char* moduleDLL)
{
	// every pe file starts with this 
	// so at its base address is the beginning of the dos header
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleDLL;
	// we then need to add the location of the nt header to the base address of the module 
	// or using types the IMAGE_DOS_HEADER + ptr to nt header e_lfanew
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(moduleDLL + dosHeader->e_lfanew);

	// export directory is located within the data section inside the optional header
	// data directory is an array which can be indexed into from 0 -15
	// 0 is the location of thge export table as it is the first directory present in the structure
	// the virtual address is the property denoting the location of the export address in memory
	IMAGE_EXPORT_DIRECTORY* exportDirectoryTable = (IMAGE_EXPORT_DIRECTORY*)(moduleDLL + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	/*
	
	Export table contains two types of function resolution 
	either by function name or function ordinal number
	Both of these values are stored in two lists 

	addressofnames - an array which stores the names of exported functions 
	address of ordinals - an array of ordinal number which represnts that function as an index
	address of functiomns - an array ofthe relative virtual address (rva) of all the exported functions


	The array of names and array of ordinals are mutually exclusive 
	They are two different ways to find a desried function 
	The better way is by name as function names once stated will not change in updates
	However ordinal numbers might if features are added or removed in the future
	So the best approach is to iterate the name array to find a function with a given name

	The next step is to link the names array to the function rva array
	This is where the array of funtion ordinals comes into play 
	If a function was at index 0 in the function name array 
	To find its function address we would go to index 0 inside the ordinal array 
	The ordinal number at index 0 would then be used to fund the function rva 
	Inside of the array of functions 
	*/

	DWORD* functionNamesArray = (DWORD*)(moduleDLL + exportDirectoryTable->AddressOfNames);
	DWORD* functionRvaArray = (DWORD*)(moduleDLL + exportDirectoryTable->AddressOfFunctions);
	WORD* functionOrdinalsArray = (WORD*)(moduleDLL + exportDirectoryTable->AddressOfNameOrdinals);

	// iterating exported functions available in table
	for (int i = 0; i < exportDirectoryTable->NumberOfFunctions; i++)
	{		
		// getting function name from name array
		char* functionName = (char*)(moduleDLL + functionNamesArray[i]);
		// function ordinal from ordinal array
		int functionOrdinalNumber = exportDirectoryTable->Base + functionOrdinalsArray[i];
		// getting function address via function ordinal from function RVA array
		//DWORD functionAddress = (DWORD)(moduleDLL + functionRvaArray[functionOrdinalNumber]);
		DWORD functionAddress = (DWORD)(moduleDLL + functionRvaArray[functionOrdinalsArray[i]]);

		if (!strcmp(exportedFunctionName, functionName))
		{
			return (char*)functionAddress;
		}
	}
}

