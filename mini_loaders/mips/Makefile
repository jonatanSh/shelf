CC=mips-linux-gnu-gcc-10
CFLAGS=-static -fpie --entry=_start -nolibc -nostartfiles
TARGETS=mips mipsbe
all: $(TARGETS)

mips:
	$(CC) $(CFLAGS) mips.s -o ../../outputs/mini_loader_mips.out

mipsbe:
	$(CC) $(CFLAGS) -BE mips.s -o ../../outputs/mini_loader_mips_be.out