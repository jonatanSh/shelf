CFLAGS=-nostartfiles --entry=main
TARGETS=mips_shellcode intel_x32_shellcode intel_x64_shellcode
OUTPUT_DIRECTORY=../outputs/
include ../makefiles/generic.mk
all: $(TARGETS)

mips_shellcode: mips_example
	python -m elf_to_shellcode ../outputs/example_mipsbe.out mips big ../outputs/example_mipsbe.out.shellcode

intel_x32_shellcode: intel_x32_example
	python -m elf_to_shellcode ../outputs/example_intel_x32.out intel_x32 little ../outputs/example_intel_x32.out.shellcode


intel_x64_shellcode: intel_x64_example
	python -m elf_to_shellcode ../outputs/example_intel_x64.out intel_x64 little ../outputs/example_intel_x64.out.shellcode