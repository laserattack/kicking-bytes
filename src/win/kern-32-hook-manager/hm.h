#ifndef HOOK_H
#define HOOK_H

// Не должно быть манглинга, т.к.
// используются в ассемблерной вставке
extern "C" {
    void hook();
    void unhook();
}

void set_payload_address(void* address);
void set_hook_address(void* address);
void* get_hook_address();
void* get_payload_address();
const char* get_function_name_by_address(void* address);

#endif // HOOK_H