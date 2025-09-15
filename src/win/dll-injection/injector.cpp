#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h> // для _access

#define DLL_NAME "inject.dll"

bool FileExists(const char* path) {
    return _access(path, 0) == 0;
}

char* GetAbsolutePath(const char* relativePath) {
    static char absolutePath[MAX_PATH];
    if (GetFullPathNameA(relativePath, MAX_PATH, absolutePath, NULL) == 0) {
        return NULL;
    }
    return absolutePath;
}

DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

void InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed. Error: %d\n", GetLastError());
        exit(-1);
    }

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        exit(-1);
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        exit(-1);
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        exit(-1);
    }
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        return 1;
    }

    const char* targetProcess = argv[1];
    const char* relativeDllPath = DLL_NAME;
    
    char* absoluteDllPath = GetAbsolutePath(relativeDllPath);
    if (!absoluteDllPath) {
        printf("Failed to get absolute path for: %s\n", relativeDllPath);
        return 1;
    }
    
    if (!FileExists(absoluteDllPath)) {
        printf("DLL file not found: %s\n", absoluteDllPath);
        return 1;
    }
    
    DWORD pid = FindProcessId(targetProcess);
    if (pid == 0) {
        printf("Process '%s' not found\n", targetProcess);
        return 1;
    }

    printf("Found process '%s' with PID: %d\n", targetProcess, pid);
    printf("Attempting injection...\n");

    InjectDLL(pid, absoluteDllPath);
    printf("Injection completed successfully!\n");

    return 0;
}