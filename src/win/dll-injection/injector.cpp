#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
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

bool IsDllAlreadyLoaded(HANDLE hProcess, const char* dllName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char moduleName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hModules[i], moduleName, MAX_PATH)) {
                const char* lastBackslash = strrchr(moduleName, '\\');
                const char* fileName = lastBackslash ? lastBackslash + 1 : moduleName;
                if (strcmpi(fileName, dllName) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

void InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed. Error: %d\n", GetLastError());
        exit(1);
    }

    if (IsDllAlreadyLoaded(hProcess, DLL_NAME)) {
        printf("DLL '%s' is already loaded in process %d\n", DLL_NAME, pid);
        CloseHandle(hProcess);
        exit(1);
    }

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        exit(1);
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        exit(1);
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        exit(1);
    }
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <-name <process_name> or -pid <process_pid>>\n", argv[0]);
        exit(1);
    }
    
    char* absoluteDllPath = GetAbsolutePath(DLL_NAME);
    if (!absoluteDllPath) {
        printf("Failed to get absolute path for: %s\n", DLL_NAME);
        exit(1);
    }
    
    if (!FileExists(absoluteDllPath)) {
        printf("DLL file not found: %s\n", absoluteDllPath);
        exit(1);
    }
	
	DWORD pid;
	if (strcmp("-name", argv[1]) == 0) {
		const char* targetProcess = argv[2];
		pid = FindProcessId(targetProcess);
		if (pid == 0) {
			printf("Process '%s' not found\n", targetProcess);
			exit(1);
		}
		printf("Found process '%s' with PID: %d\n", targetProcess, pid);
	} else if (strcmp("-pid", argv[1]) == 0) {
		char* endPtr;
		pid = (DWORD)strtoul(argv[2], &endPtr, 10);
	} else {
		printf("Invalid argument '%s'", argv[1]);
		exit(1);
	}
   
    printf("Attempting injection...\n");

    InjectDLL(pid, absoluteDllPath);
    printf("Injection completed successfully!\n");

    return 0;
}