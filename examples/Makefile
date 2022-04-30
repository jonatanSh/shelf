TARGETS=mips
MIPS_CC=mips-linux-gnu-gcc-10
CFLAGS=-fno-stack-protector -fPIE -fpic -static -nostartfiles --entry=main
all: $(TARGETS)

mips:
	$(MIPS_CC) $(CFLAGS) main.c -o ../outputs/example.out