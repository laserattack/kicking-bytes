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

// extern "C" чтобы не было манглинга
extern "C" {
	void payload();
	void hook();
	void unhook();
	void hooked();
}

void* hookAddr; 	   					  // адрес хука
uint8_t originalBytes[HOOK_SIZE] = { 0 }; // сюда сохраняются оригинальные байты

int main() {
	HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
	
    hookAddr = (void*)GetProcAddress(hKernel32, "CreateFileA");
	
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
    return 0;
}

void payload() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] Hooked\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void hook() {
    memcpy(originalBytes, hookAddr, HOOK_SIZE);
    DWORD oldProtect;
    VirtualProtect(hookAddr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    void* h = (void*)hooked;
    // mov r11, АДРЕС_ФУНКЦИИ + jmp r11
    uint8_t patch[HOOK_SIZE] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 };
    memcpy(patch + 2, &h, sizeof(void*));
    memcpy(hookAddr, patch, HOOK_SIZE);
    VirtualProtect(hookAddr, HOOK_SIZE, oldProtect, &oldProtect);
}

void unhook() {
    DWORD oldProtect;
    VirtualProtect((void*)hookAddr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)hookAddr, originalBytes, HOOK_SIZE);
    VirtualProtect((void*)hookAddr, HOOK_SIZE, oldProtect, &oldProtect);
}

/*
1.  Адрес возврата в r15
2.  Сохраняет значения всех регистров на стеке
3.  Вызывает полезную нагрузку
4.  Снимает хук
5.  Восстанавливает значения регистров
6.  Вызывает оригинальную ф-ю
7.  Сохраняет значения всех регистров на стеке
8.  Ставит хук назад
9.  Восстанавливает значения регистров
10. Прыгает к след. инструкцию вызывающего кода по адресу из r15
*/

__attribute__((naked))
void hooked() {
    asm volatile (
		"pop %%r15\n"
		PUSH_ALL_REGS
        "call payload\n"
		"call unhook\n"
		POP_ALL_REGS
        "movq hookAddr(%%rip), %%rax\n"
        "call *%%rax\n"
		PUSH_ALL_REGS
        "call hook\n"
		POP_ALL_REGS
        "jmp *%%r15\n"
		:
    );
}