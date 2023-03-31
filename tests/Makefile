include ../makefiles/generic.mk
OUTPUT_DIRECTORY=../outputs/
MIPS_TARGETS=mips_elf_features
INTEL_X32=intel_x32_elf_features no_libc_intel_x32_no_relocations
INTEL_X64+=intel_x64_elf_features
AARCH64=aarch64_elf_features no_libc_aarch64_no_relocations
ARM32=arm32_elf_features
TESTS+=$(MIPS_TARGETS)
TESTS+=$(INTEL_X32)
TESTS+=$(INTEL_X64)
TESTS+=$(AARCH64)
TESTS+=$(ARM32)

C_FILES=../osals/sprintf.c
OSAL_FILES+=../osals/string.c ../osals/linux/syscalls_wrapper/unistd.c

.PHONY: clean all

all: hooks $(TESTS)

mips: $(MIPS_TARGETS)
intel_x32: $(INTEL_X32)
intel_x64: $(INTEL_X64)
aarch64: $(AARCH64)
arm32: $(ARM32)

hooks:
	cd ../hooks && $(MAKE)

no_libc_intel_x32_%: mini_loader_x32
	$(X32_CC) -masm=intel -shared -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst no_libc_intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

no_libc_aarch64_%: mini_loader_arm_x64
	$(AARCH64_CC) -static $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst no_libc_aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode

clean:
	rm -rf ../outputs/*elf_features*.out*
	rm -rf ../outputs/*no_relocations*.out*
	cd ../mini_loaders && python compile.py --action clean
