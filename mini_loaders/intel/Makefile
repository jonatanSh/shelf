CC=nasm
OBJCOPY=i686-linux-gnu-objcopy
TARGETS=x32
all: $(TARGETS)

x32:
	$(CC) -f elf -o ../../outputs/mini_loader_x32.out x32.s
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x32.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x32.shellcode
