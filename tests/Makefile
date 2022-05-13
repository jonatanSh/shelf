MIPS_CC=mips-linux-gnu-gcc
X32_CC=i686-linux-gnu-gcc
X64_CC=i686-linux-gnu-gcc -m64
CFLAGS=-fno-stack-protector -fPIE -fpic -static -nostartfiles --entry=main
TARGETS=mips_shellcode intel_x32_shellcode intel_x64_shellcode

all: $(TARGETS)

mips:
	$(MIPS_CC) $(CFLAGS) -BE main.c -o ../outputs/example_mipsbe.out

mips_shellcode: mips
	python -m elf_to_shellcode ../outputs/example_mipsbe.out mips big ../outputs/example_mipsbe.out.shellcode

intel_x32:
	$(X32_CC) $(CFLAGS) main.c -o ../outputs/example_intel_x32.out

intel_x32_shellcode: intel_x32
	python -m elf_to_shellcode ../outputs/example_intel_x32.out intel_x32 little ../outputs/example_intel_x32.out.shellcode


intel_x64:
	$(X64_CC) $(CFLAGS) main.c -o ../outputs/example_intel_x64.out

intel_x64_shellcode: intel_x64
	python -m elf_to_shellcode ../outputs/example_intel_x64.out intel_x64 little ../outputs/example_intel_x64.out.shellcode