CC=i686-linux-gnu-gcc
OBJCOPY=i686-linux-gnu-objcopy
CFLAGS=-masm=intel -static -fpie -s --entry=_start -nolibc -nostartfiles
TARGETS=x32
all: $(TARGETS)

x32:
	$(CC) $(CFLAGS) x32.s -o ../../outputs/mini_loader_x32.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x32.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x32.shellcode
