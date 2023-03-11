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

no_libc_intel_x32_%:
	$(X32_CC) -masm=intel -shared -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst no_libc_intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out --arch intel_x32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_intel_x32_,,$@)_intel_x32.out.shellcode --loader-support dynamic

no_libc_aarch64_%:
	$(AARCH64_CC) -static $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst no_libc_aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst no_libc_aarch64_,,$@)_aarch64.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_aarch64_,,$@)_aarch64.out --arch aarch64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst no_libc_aarch64_,,$@)_aarch64.out.shellcode

dynamic_mips_%:
	$(MIPS_CC) -DOSAL_LIBC -DARCH_MIPS -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) $(NOLIBC) -static -nolibc  -shared -lm -lc -lgcc -lc  -BE $(subst dynamic_mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out --arch mips --endian big --output ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out.shellcode --loader-support dynamic

dynamic_intel_x32_%:
	$(X32_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_intel_x32_,,$@).c  -o $(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out --arch intel_x32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out.shellcode --loader-support dynamic

dynamic_intel_x64_%:
	$(X64_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_intel_x64_,,$@).c  -o $(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out --arch intel_x64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out.shellcode --loader-support dynamic

dynamic_arm32_%:
	$(ARM_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_arm32_,,$@).c  -o $(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out --arch arm32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out.shellcode --loader-support dynamic

dynamic_aarch64_%:
	$(AARCH64_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst dynamic_aarch64_,,$@).c  -o $(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out --arch aarch64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out.shellcode --loader-support dynamic


clean:
	rm -rf ../outputs/*elf_features*.out*
	rm -rf ../outputs/*no_relocations*.out*
	cd ../mini_loaders python compile.py --action clean
