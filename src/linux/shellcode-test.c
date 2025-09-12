#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Функция для чтения бинарного файла в память
unsigned char* read_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char* buffer = malloc(*size);
    if (!buffer) {
        perror("malloc");
        fclose(file);
        return NULL;
    }
    
    if (fread(buffer, 1, *size, file) != *size) {
        perror("fread");
        free(buffer);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    return buffer;
}

int main() {
    size_t size;
    unsigned char* shellcode = read_file("shellcode", &size);
    
    if (!shellcode) {
        fprintf(stderr, "Failed to read shellcode.bin\n");
        return 1;
    }
    
    printf("Loaded shellcode size: %zu bytes\n", size);
    printf("Shellcode bytes: ");
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\n");
    
    // Выделяем память с правами исполнения
    void* exec_mem = mmap(NULL, size, 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        free(shellcode);
        return 1;
    }
    
    // Копируем shellcode в исполняемую память
    memcpy(exec_mem, shellcode, size);
    
    // Преобразуем в функцию и вызываем
    void (*func)() = (void(*)())exec_mem;
    
    printf("Executing shellcode...\n");
    func();
    printf("Shellcode executed successfully!\n");
    
    // Очистка
    munmap(exec_mem, size);
    free(shellcode);
    
    return 0;
}
