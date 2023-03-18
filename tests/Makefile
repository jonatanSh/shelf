include ../makefiles/generic.mk
OUTPUT_DIRECTORY=../outputs/
MIPS_TARGETS=mips_elf_features mips_dynamic_elf_features
INTEL_X32=intel_x32_elf_features intel_x32_no_libc_no_relocations
INTEL_X32+=intel_x32_dynamic_elf_features
INTEL_X64+=intel_x64_elf_features intel_x64_dynamic_elf_features
AARCH64=aarch64_elf_features aarch64_no_libc_no_relocations aarch64_dynamic_elf_features
ARM32=arm32_elf_features arm32_dynamic_elf_features
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

intel_x32_no_libc_%:
	$(X32_CC) -masm=intel -shared -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst intel_x32_no_libc_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

aarch64_no_libc_%:
	$(AARCH64_CC) -static $(CFLAGS) $(C_FILES) $(OSAL_FILES) -nolibc $(subst aarch64_no_libc_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode

mips_dynamic_%:
	$(MIPS_CC) -DOSAL_LIBC -DARCH_MIPS -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) $(NOLIBC) -static -nolibc  -shared -lm -lc -lgcc -lc  -BE $(subst mips_dynamic_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

intel_x32_dynamic_%:
	$(X32_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst intel_x32_dynamic_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

intel_x64_dynamic_%:
	$(X64_CC) -masm=intel -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst intel_x64_dynamic_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

arm32_dynamic_%:
	$(ARM_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst arm32_dynamic_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic

aarch64_dynamic_%:
	$(AARCH64_CC) -DOSAL_LIBC -DDYNAMIC_SUPPORT $(CFLAGS) $(C_FILES) $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(subst aarch64_dynamic_,,$@).c  -o $(OUTPUT_DIRECTORY)$@.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$@.out --output ../outputs/$(OUTPUT_DIRECTORY)$@.out.shellcode --loader-support dynamic


clean:
	rm -rf ../outputs/*elf_features*.out*
	rm -rf ../outputs/*no_relocations*.out*
	cd ../mini_loaders python compile.py --action clean
