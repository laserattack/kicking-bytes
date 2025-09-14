// g++ -m64 main.cpp && a.exe && del a.exe

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

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

void payload();
void hook();
void unhook();
void hooked();

void* payloadAddr; 					      // адрес полезной нагрузки
void* hookAddr; 	   					  // адрес хука
void* setHookAddr;						  // адрес функции которая ставит хук
void* delHookAddr;						  // адрес функции которая снимает хук

uint8_t originalBytes[HOOK_SIZE] = { 0 }; // сюда сохраняются оригинальные байты

void testHookCreateFileA();

int main() {
	printf("	testHookCreateFileA\n");
    testHookCreateFileA();
    return 0;
}

void testHookCreateFileA() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    payloadAddr = (void*)payload;
    hookAddr = (void*)GetProcAddress(hKernel32, "CreateFileA");
	setHookAddr = (void*)hook;
	delHookAddr = (void*)unhook;
	
	hook();

	for (int i = 0; i < 10; ++i) {
		
		HANDLE hFile = CreateFileA(
			"testfile.tmp",
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		CloseHandle(hFile);
		DeleteFileA("testfile.tmp");
			
	}

    unhook();
	
    FreeLibrary(hKernel32);
    printf("Good job!\n");
}

void payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] Hooked\n", 
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// Установка хука
void hook() {
    memcpy(originalBytes, hookAddr, HOOK_SIZE);
    DWORD oldProtect;
    VirtualProtect(hookAddr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    void* hkd = (void*)hooked;
    // mov r11, АДРЕС_ФУНКЦИИ + jmp r11
    uint8_t patch[HOOK_SIZE] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 };
    memcpy(patch + 2, &hkd, sizeof(void*));
    memcpy(hookAddr, patch, HOOK_SIZE);
    VirtualProtect(hookAddr, HOOK_SIZE, oldProtect, &oldProtect);
}

void unhook() {
    DWORD oldProtect;
    VirtualProtect((void*)hookAddr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)hookAddr, originalBytes, HOOK_SIZE);
    VirtualProtect((void*)hookAddr, HOOK_SIZE, oldProtect, &oldProtect);
}

__attribute__((naked))
void hooked() {
	
    asm volatile (
        // Адрес возврата в r15
		"pop %%r15\n"
		
		PUSH_ALL_REGS
        
        // Вызываем payload функцию
        "movq payloadAddr(%%rip), %%rax\n"
        "call *%%rax\n"
		
		// удаляем хук чтобы вызвать оригинальную ф-ю
		"movq delHookAddr(%%rip), %%rax\n"
        "call *%%rax\n"
		
        // Восстанавливаем регистры
		POP_ALL_REGS
		
        // Вызываем оригинальную функцию
        "movq hookAddr(%%rip), %%rax\n"
        "call *%%rax\n"
		
		PUSH_ALL_REGS
        
        // Устанавливаем хук обратно
        "movq setHookAddr(%%rip), %%rax\n"
        "call *%%rax\n"
        
		POP_ALL_REGS
		
        // Возвращаемся к вызывающему коду
        "jmp *%%r15\n"
        :
        :
        : "memory"
    );
}
