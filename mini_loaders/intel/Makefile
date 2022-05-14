OBJCOPY=i686-linux-gnu-objcopy
TARGETS=x32 x64
X32_CC=i686-linux-gnu-gcc
X64_CC=i686-linux-gnu-gcc -m64
CFLAGS=-static -nolibc -nostartfiles -g -Wno-stack-protector -masm=intel -fno-plt -fno-pic --entry=loader_main 

all: $(TARGETS)

x32:
	$(X32_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_x32.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x32.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x32.shellcode


x64:
	$(X64_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_x64.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x64.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x64.shellcode
