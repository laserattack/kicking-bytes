#include "hm.h"

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

#define HOOK_SIZE 13

#define PUSH_ALL_REGS \
    "push %%r15\n" \
    "push %%r14\n" \
    "push %%r13\n" \
    "push %%r12\n" \
    "push %%r11\n" \
    "push %%r10\n" \
    "push %%r9\n" \
    "push %%r8\n" \
    "push %%rbp\n" \
    "push %%rdi\n" \
    "push %%rsi\n" \
    "push %%rdx\n" \
    "push %%rcx\n" \
    "push %%rbx\n" \
    "push %%rax\n" \
    "pushfq\n"

#define POP_ALL_REGS \
    "popfq\n" \
    "pop %%rax\n" \
    "pop %%rbx\n" \
    "pop %%rcx\n" \
    "pop %%rdx\n" \
    "pop %%rsi\n" \
    "pop %%rdi\n" \
    "pop %%rbp\n" \
    "pop %%r8\n" \
    "pop %%r9\n" \
    "pop %%r10\n" \
    "pop %%r11\n" \
    "pop %%r12\n" \
    "pop %%r13\n" \
    "pop %%r14\n" \
    "pop %%r15\n"

static void* hook_addr = NULL;                       // адрес хука
static void* payload_addr = NULL;					 // адрес полезной нагрузки
static uint8_t original_bytes[HOOK_SIZE] = { 0 };    // оригинальные байты
static void hooked();								 // эта ф-я вызывается вместо хукаемой

void set_hook_address(void* address) { hook_addr = address; }
void* get_hook_address() { return hook_addr; }
void set_payload_address(void* address) { payload_addr = address; }
void* get_payload_address() { return payload_addr; }

void hook() {
    if (!hook_addr || !payload_addr) return;
    
    memcpy(original_bytes, hook_addr, HOOK_SIZE);
    DWORD old_protect;
    VirtualProtect(hook_addr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old_protect);
    void* h = (void*)hooked;
    // mov r11, АДРЕС_ФУНКЦИИ + jmp r11
    uint8_t patch[HOOK_SIZE] = { 
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 
    };
    memcpy(patch + 2, &h, sizeof(void*));
    memcpy(hook_addr, patch, HOOK_SIZE);
    VirtualProtect(hook_addr, HOOK_SIZE, old_protect, &old_protect);
}

void unhook() {
    if (!hook_addr || !payload_addr) return;
    
    DWORD old_protect;
    VirtualProtect((void*)hook_addr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy((void*)hook_addr, original_bytes, HOOK_SIZE);
    VirtualProtect((void*)hook_addr, HOOK_SIZE, old_protect, &old_protect);
}

__attribute__((naked))
static void hooked() {
    asm volatile (
        "pop %%r15\n"
        PUSH_ALL_REGS
        "movq %0, %%rax\n"
        "call *%%rax\n"
        "call unhook\n"
        POP_ALL_REGS
        "movq %1, %%rax\n"
        "call *%%rax\n"
        PUSH_ALL_REGS
        "call hook\n"
        POP_ALL_REGS
        "jmp *%%r15\n"
        :
        : "m" (payload_addr), "m" (hook_addr)
    );
}

static bool try_get_function_name(void* address, HMODULE hModule, char* result, size_t result_size) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return false;
    
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD_PTR functionRva = (DWORD_PTR)address - (DWORD_PTR)hModule;
    
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        DWORD functionIndex = ordinals[i];
        if (functionIndex < exportDirectory->NumberOfFunctions && functions[functionIndex] == functionRva) {
            const char* functionName = (const char*)((BYTE*)hModule + names[i]);
            snprintf(result, result_size, "%s", functionName);
            return true;
        }
    }
    
    return false;
}

const char* get_function_name_by_address(void* address) {
    static char result[256] = {0};
    
    HMODULE hModule = NULL;
    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)address, &hModule)) {
        if (try_get_function_name(address, hModule, result, sizeof(result))) {
            return result;
        }
    }
    snprintf(result, sizeof(result), "0x%p", address);
    return result;
}