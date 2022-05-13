CFLAGS=-nostartfiles --entry=main
include ../makefiles/generic.mk
OUTPUT_DIRECTORY=../outputs/
TESTS=mips_elf_features intel_x32_elf_features intel_x64_elf_features
TESTS+=no_libc_mips_no_relocations no_libc_intel_x32_no_relocations
TESTS+=no_libc_intel_x64_no_relocations
all: $(TESTS)


no_libc_mips_%:
	$(MIPS_CC) $(CFLAGS) -nolibc -BE $(subst no_libc_mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_mips_,,$@)_mipsbe.out
	python -m elf_to_shellcode ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_mips_,,$@)_mipsbe.out mips big ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_mips_,,$@)_mipsbe.out.shellcode
no_libc_intel_x32_%:
	$(X32_CC) $(CFLAGS) -nolibc $(subst no_libc_intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out
	python -m elf_to_shellcode ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out intel_x32 little ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out.shellcode

no_libc_intel_x64_%:
	$(X64_CC) $(CFLAGS) -nolibc $(subst no_libc_intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_intel_x64_,,$@)_intel_x64.out
	python -m elf_to_shellcode ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x64_,,$@)_intel_x64.out intel_x64 little ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x64_,,$@)_intel_x64.out.shellcode
