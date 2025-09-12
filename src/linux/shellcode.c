/*
gcc -nostdlib shellcode.c -o shellcode
objcopy -O binary -j .text shellcode shellcode
gcc shellcode-test.c -o shellcode-test
./shellcode-test
rm shellcode shellcode-test
*/

#define SYS_WRITE 1
#define SYS_EXIT 60

#define syscall0(num) \
    asm volatile ("syscall" : : "a"(num))

#define syscall3(num, arg1, arg2, arg3) \
    asm volatile ("syscall" : : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3))

void _start() {
    char msg[] = {'h', 'e', 'l', 'l', 'o', 0x0a, 0x00};
    unsigned long len = sizeof(msg) - 1;
    
    for (int i = 0; i < 10; ++i) {
        syscall3(SYS_WRITE, 1, msg, len);
    }
    syscall0(SYS_EXIT);
}
