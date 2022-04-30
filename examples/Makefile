TARGETS=mips mips_shellcode
MIPS_CC=mips-linux-gnu-gcc-10
CFLAGS=-fno-stack-protector -fPIE -fpic -static -nostartfiles --entry=main
all: $(TARGETS)

mips:
	$(MIPS_CC) $(CFLAGS) -BE main.c -o ../outputs/example_mipsbe.out

mips_shellcode:
	python ../elf_to_shellcode/main.py ../outputs/example_mipsbe.out mips big ../outputs/example_mipsbe.out.shellcode