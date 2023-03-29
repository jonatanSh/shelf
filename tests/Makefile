include ../makefiles/generic.mk
OUTPUT_DIRECTORY=../outputs/
MIPS_TARGETS=mips_elf_features dynamic_mips_elf_features
INTEL_X32=intel_x32_elf_features no_libc_intel_x32_no_relocations
INTEL_X32+=dynamic_intel_x32_elf_features
INTEL_X64+=intel_x64_elf_features dynamic_intel_x64_elf_features
AARCH64=aarch64_elf_features no_libc_aarch64_no_relocations dynamic_aarch64_elf_features
ARM32=arm32_elf_features dynamic_arm32_elf_features
TESTS+=$(MIPS_TARGETS)
TESTS+=$(INTEL_X32)
TESTS+=$(INTEL_X64)
TESTS+=$(AARCH64)
TESTS+=$(ARM32)

C_FILES=../osals/sprintf.c
OSAL_FILES+=../osals/string.c ../osals/linux/syscalls_wrapper/unistd.c

.PHONY: clean all

all: clean hooks $(TESTS)

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

dynamic_mips_%: mini_loader_mips mini_loader_mipsbe
	$(MIPS_CC) -DOSAL_LIBC -DARCH_MIPS -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) $(NOLIBC) -static -nolibc  -shared -lm -lc -lgcc -lc  -BE $(subst dynamic_mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

dynamic_intel_x32_%: mini_loader_x32
	$(X32_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_intel_x32_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

dynamic_intel_x64_%: mini_loader_x64
	$(X64_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_intel_x64_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

dynamic_arm32_%: mini_loader_arm_x32
	$(ARM_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_arm32_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

dynamic_aarch64_%: mini_loader_arm_x64
	$(AARCH64_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_aarch64_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m shelf --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic


clean:
	rm -rf ../outputs/*elf_features*.out*
	rm -rf ../outputs/*no_relocations*.out*
	cd ../mini_loaders && python compile.py --action clean
