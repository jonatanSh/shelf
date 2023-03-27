CFLAGS+=-fno-stack-protector -fPIE -fpic
CFLAGS+=-nostartfiles --entry=main
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/compilers.mk

dir_guard:
	mkdir -p $(SELF_DIR)/../outputs



mini_loader_%: dir_guard
	cd $(SELF_DIR)/../mini_loaders && python compile.py --action make --arch $(subst mini_loader_,,$@)

shellcode_%: dir_guard
	python3 -m elf_to_shellcode --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.shellcode
	python3 -m elf_to_shellcode --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/simple_hello_hook.py
	python3 -m elf_to_shellcode --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.eshelf --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.eshelf.shellcode --output-format eshelf
	python3 -m elf_to_shellcode --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.rwx_bypass.shellcode --mitigation-bypass rwx


mips_%: mini_loader_mips mini_loader_mipsbe
	$(MIPS_CC) $(CFLAGS) $(C_FILES) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(MIPS_CC) $(CFLAGS) $(C_FILES) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out.eshelf -DESHELF
	$(MAKE) shellcode_$@


intel_x32_%: mini_loader_x32
	$(X32_CC) -masm=intel $(CFLAGS) $(subst intel_x32_,,$@).c $(C_FILES) -static -o $(OUTPUT_DIRECTORY)$@.out
	$(X32_CC) -masm=intel $(CFLAGS) $(subst intel_x32_,,$@).c $(C_FILES) -static -o $(OUTPUT_DIRECTORY)$@.out.eshelf -DESHELF
	$(MAKE) shellcode_$@


intel_x64_%: mini_loader_x64
	$(X64_CC) -masm=intel $(CFLAGS) $(C_FILES) -static $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_CC) -masm=intel $(CFLAGS) $(C_FILES) -static $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out.eshelf -DESHELF
	$(MAKE) shellcode_$@

arm32_%: mini_loader_arm_x32
	$(ARM_CC) $(CFLAGS) $(C_FILES) -static $(subst arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(ARM_CC) $(CFLAGS) $(C_FILES) -static $(subst arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out.eshelf -DESHELF
	$(MAKE) shellcode_$@

aarch64_%: mini_loader_arm_x64
	$(AARCH64_CC) $(CFLAGS) $(C_FILES) -static $(subst aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(AARCH64_CC) $(CFLAGS) $(C_FILES) -DESHELF -static $(subst aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out.eshelf
	$(MAKE) shellcode_$@
