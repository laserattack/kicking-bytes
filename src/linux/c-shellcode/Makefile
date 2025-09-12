CC = gcc
OBJCOPY = objcopy

all: shellcode.elf shellcode.bin shellcode-test.elf

shellcode.elf: shellcode.c
	# $(CC) -fcf-protection=none -nostdlib shellcode.c -o shellcode.elf
	$(CC) -nostdlib shellcode.c -o shellcode.elf

shellcode.bin: shellcode.elf
	$(OBJCOPY) -O binary -j .text shellcode.elf shellcode.bin

shellcode-test.elf: shellcode-test.c
	$(CC) shellcode-test.c -o shellcode-test.elf

run: shellcode-test.elf shellcode.bin
	./shellcode-test.elf

clean:
	rm -f shellcode.elf shellcode.bin shellcode-test.elf

.PHONY: all run clean
