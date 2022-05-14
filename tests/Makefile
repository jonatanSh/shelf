CFLAGS=-nostartfiles --entry=main
include ../makefiles/generic.mk
OUTPUT_DIRECTORY=../outputs/
TESTS=mips_elf_features intel_x32_elf_features intel_x64_elf_features arm_32_elf_features
TESTS+=no_libc_intel_x32_no_relocations
all: $(TESTS)


no_libc_intel_x32_%:
	$(X32_CC) $(CFLAGS) -nolibc $(subst no_libc_intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out
	python -m elf_to_shellcode ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out intel_x32 little ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out.shellcode
