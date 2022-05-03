TARGETS=mips mips_shellcode
MIPS_CC=mips-linux-gnu-gcc
CFLAGS=-fno-stack-protector -fPIE -fpic -static -nostartfiles --entry=main
all: $(TARGETS)

mips:
	$(MIPS_CC) $(CFLAGS) -BE main.c -o ../outputs/example_mipsbe.out

mips_shellcode:
	python -m elf_to_shellcode ../outputs/example_mipsbe.out mips big ../outputs/example_mipsbe.out.shellcode