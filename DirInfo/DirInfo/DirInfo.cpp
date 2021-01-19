/*
 * A sample program that uses FindFirstFile and FindNextFile 
 * to list all of the files in a directory.
 */

#include <windows.h>
#include <stdio.h>

void ShowDirectory(wchar_t*);
char GetChar();

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        printf("Usage: dirinfo.exe <directory_path>");
        exit(1);
    }

    do {
        ShowDirectory(argv[1]);
        printf("---------------------\n1. Show selected dir. \n2. Exit.\n\n");
    } while (GetChar() != '2');
    
}

char GetChar() {
    char in, next = getchar();
    do {
        in = next;
    } while ((next = getchar()) != '\n');
    return in;
}

void ShowDirectory(wchar_t* dir_name) 
{
    WIN32_FIND_DATA file_struct;
    HANDLE file_handle;

    file_handle = FindFirstFile(dir_name, &file_struct);

    if (file_handle == INVALID_HANDLE_VALUE) {
        printf("Call to FindFirstFile failed with error code %d", GetLastError());
        exit(1);
    }

    do {
        wprintf(L"%s\n", file_struct.cFileName);
    } while (FindNextFile(file_handle, &file_struct));

    FindClose(file_handle);
}
