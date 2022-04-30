CC=mips-linux-gnu-gcc-10
OBJCOPY=mips-linux-gnu-objcopy
CFLAGS=-static -fpie --entry=_start -nolibc -nostartfiles
TARGETS=mips mipsbe
all: $(TARGETS)

mips:
	$(CC) $(CFLAGS) mips.s -o ../../outputs/mini_loader_mips.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../outputs/mini_loader_mips.shellcode.out

mipsbe:
	$(CC) $(CFLAGS) -BE mips.s -o ../../outputs/mini_loader_mips_be.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../outputs/mini_loader_mipsbe.shellcode.out
	