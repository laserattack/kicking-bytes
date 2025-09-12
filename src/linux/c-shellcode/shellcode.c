#define exit(num) \
    asm volatile ( \
        "mov %0, %%rdi\n" \
        "mov $60, %%rax\n" \
        "syscall\n" \
        : \
        : "r"((long)num) \
        : "rax", "rdi", "rcx", "r11" \
    )

#define write(fd, buf, count) \
    asm volatile ( \
        "mov $1, %%rax\n" \
        "mov %0, %%rdi\n" \
        "mov %1, %%rsi\n" \
        "mov %2, %%rdx\n" \
        "syscall\n" \
        : \
        : "r"((long)fd), "r"(buf), "r"((long)count) \
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11" \
    )

void _start() {
    char msg[] = {
        'h', 'e', 'l', 'l', 'o', ' ',
        's', 'a', 'i', 'l', 'o', 'r', '!',
        0x0a, 0x00
    };
    unsigned long len = sizeof(msg) - 1;
    
    for (int i = 0; i < 10; ++i) {
        write(1, msg, len);
    }

    exit(0);
}
