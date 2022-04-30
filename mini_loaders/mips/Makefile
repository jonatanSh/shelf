CC=mips-linux-gnu-gcc
OBJCOPY=mips-linux-gnu-objcopy
CFLAGS=-static -fpie --entry=_start -nolibc -nostartfiles
TARGETS=mips mipsbe
all: $(TARGETS)

mips:
	$(CC) $(CFLAGS) mips.s -o ../../outputs/mini_loader_mips.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mips.shellcode

mipsbe:
	$(CC) $(CFLAGS) -BE mips.s -o ../../outputs/mini_loader_mips_be.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mipsbe.shellcode
	