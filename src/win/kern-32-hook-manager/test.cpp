#include <Windows.h>
#include <stdio.h>
#include "hm.h"

void payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    void* hookAddr = get_hook_address();
    const char* funcName = get_function_name_by_address(hookAddr);
    
    printf("[%02d:%02d:%02d.%03d] Hooked 0x%p;%s :)\n", 
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
           hookAddr, funcName);
}

void test_hook_CreateFileA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "CreateFileA"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        HANDLE hFile = CreateFileA(
            "testfile.tmp",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
        DeleteFileA("testfile.tmp");
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	CreateFileA test completed\n");
}

void test_hook_DeleteFileA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "DeleteFileA"));
    set_payload_address((void*)payload);
    
    hook();

    // Создаем файл для удаления
    for (int i = 0; i < 3; ++i) {
        HANDLE hFile = CreateFileA(
            "tempfile.tmp",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            DeleteFileA("tempfile.tmp"); // Будет срабатывать хук
        }
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	DeleteFileA test completed\n");
}

void test_hook_CreateDirectoryA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "CreateDirectoryA"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        char dirName[20];
        sprintf_s(dirName, "test_dir_%d", i);
        
        BOOL result = CreateDirectoryA(dirName, NULL);
        if (result) {
            RemoveDirectoryA(dirName);
        } else {
			exit(-1);
		}
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	CreateDirectoryA test completed\n");
}

void test_hook_GetCurrentDirectory() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "GetCurrentDirectoryA"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        char buffer[MAX_PATH];
        DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
        // printf("Current directory: %s\n", buffer);
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	GetCurrentDirectoryA test completed\n");
}

void test_hook_GetSystemTime() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "GetSystemTime"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        SYSTEMTIME st;
        GetSystemTime(&st);
        // printf("System time: %02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	GetSystemTime test completed\n");
}

void test_hook_Sleep() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "Sleep"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        // printf("Sleeping for 100ms...\n");
        Sleep(100);
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	Sleep test completed\n");
}

void test_hook_Beep() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "Beep"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 5; ++i) {
        // printf("Beeping...\n");
        Beep(440, 100); // 440 Hz, 100 ms
        Sleep(200);
    }

    unhook();
    
    FreeLibrary(hKernel32);
    // printf("	Beep test completed\n");
}

void test_hook_GetTickCount() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    set_hook_address((void*)GetProcAddress(hKernel32, "GetTickCount"));
    set_payload_address((void*)payload);
    
    hook();

    for (int i = 0; i < 3; ++i) {
        DWORD tickCount = GetTickCount();
        // printf("Tick count: %lu\n", tickCount);
        Sleep(100);
    }

    unhook();
	
	FreeLibrary(hKernel32);
	// printf("	GetTickCount test completed\n");
}

int main() {
	test_hook_CreateFileA();
	test_hook_DeleteFileA();
	test_hook_CreateDirectoryA();
	test_hook_GetCurrentDirectory();
	test_hook_GetSystemTime();
	test_hook_Sleep();
	test_hook_Beep();
	test_hook_GetTickCount();
    printf("Good job!\n");
    return 0;
}