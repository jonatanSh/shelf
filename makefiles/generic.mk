CFLAGS+=-fno-stack-protector -fPIE -fpic
CFLAGS+=-nostartfiles --entry=main
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/compilers.mk

mips_%:
	$(MIPS_CC) $(CFLAGS) $(C_FILES) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out --arch mips --endian big --output ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out.shellcode
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out --arch mips --endian big --output ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/test.json

	$(MIPS_CC) $(CFLAGS) $(C_FILES) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe_eshelf.out -DESHELF
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe_eshelf.out --arch mips --endian big --output ../outputs/$(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out.shellcode.eshelf --output-format eshelf



intel_x32_%:
	$(X32_CC) -masm=intel $(CFLAGS) $(subst intel_x32_,,$@).c $(C_FILES) -static -o $(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out --arch intel_x32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out.shellcode
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out --arch intel_x32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/test.json

	$(X32_CC) -masm=intel $(CFLAGS) $(subst intel_x32_,,$@).c $(C_FILES) -static -o $(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32_eshelf.out -DESHELF
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32_eshelf.out --arch intel_x32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x32_,,$@)_intel_x32.out.shellcode.eshelf --output-format eshelf


intel_x64_%:
	$(X64_CC) -masm=intel $(CFLAGS) $(C_FILES) -static $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out
	$(X64_CC) -masm=intel $(CFLAGS) $(C_FILES) -static $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64_eshelf.out -DESHELF

	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out --arch intel_x64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out.shellcode
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out --arch intel_x64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/test.json
	
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64_eshelf.out --arch intel_x64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst intel_x64_,,$@)_intel_x64.out.shellcode.eshelf --output-format eshelf

arm32_%:
	$(ARM_CC) $(CFLAGS) $(C_FILES) -static $(subst arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out --arch arm32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out.shellcode
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out --arch arm32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/test.json

	$(ARM_CC) $(CFLAGS) $(C_FILES) -static $(subst arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32_eshelf.out -DESHELF
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32_eshelf.out --arch arm32 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst arm32_,,$@)_arm32.out.shellcode.eshelf --output-format eshelf

aarch64_%:
	$(AARCH64_CC) $(CFLAGS) $(C_FILES) -static $(subst aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out
	python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out --arch aarch64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out.shellcode
	#python3 -m elf_to_shellcode --input ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out --arch aarch64 --endian little --output ../outputs/$(OUTPUT_DIRECTORY)$(subst aarch64_,,$@)_aarch64.out.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/test.json
