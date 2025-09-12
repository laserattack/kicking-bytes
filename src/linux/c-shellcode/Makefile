CC = gcc
OBJCOPY = objcopy

SOURCE = shellcode.c
ELF = shellcode.elf
BIN = shellcode.bin

LOADER_SOURCE = shellcode-test.c
LOADER_ELF = shellcode-test.elf

all: $(ELF) $(BIN) $(LOADER_ELF)

$(ELF): $(SOURCE)
	# $(CC) -fcf-protection=none -nostdlib $(SOURCE) -o $(ELF)
	$(CC) -nostdlib $(SOURCE) -o $(ELF)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary -j .text $(ELF) $(BIN)

$(LOADER_ELF): $(LOADER_SOURCE)
	$(CC) $(LOADER_SOURCE) -o $(LOADER_ELF)

run: $(LOADER_ELF) $(BIN)
	./$(LOADER_ELF) $(BIN)

clean:
	rm -f $(ELF) $(BIN) $(LOADER_ELF)

.PHONY: all run clean
