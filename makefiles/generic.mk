CFLAGS+=-fno-stack-protector -fPIE -fpic
CFLAGS+=-nostartfiles --entry=main
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/compilers.mk

dir_guard:
	mkdir -p $(SELF_DIR)/../outputs



mini_loader_%: dir_guard
	cd $(SELF_DIR)/../mini_loaders && python compile.py --action make --arch $(subst mini_loader_,,$@)

shellcode_%: dir_guard
	python3 -m shelf --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.shellcode
	python3 -m shelf --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.hooks.shellcode --loader-supports hooks --hooks-configuration ../hook_configurations/simple_hello_hook.py
	python3 -m shelf --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.eshelf --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.eshelf.shellcode --output-format eshelf
	python3 -m shelf --input $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out --output $(OUTPUT_DIRECTORY)/$(subst shellcode_,,$@).out.rwx_bypass.shellcode --mitigation-bypass rwx

geneirc_compile:
	$(COMPILER) $(COMPILER_FLAGS) $(FILES) -o $(OUTPUT_FILE)

geneirc_compile_eshelf:
	$(COMPILER) $(COMPILER_FLAGS) $(FILES) -o $(OUTPUT_FILE).eshelf -DESHELF

compile_all:
	$(MAKE) geneirc_compile COMPILER="$(COMPILER)" COMPILER_FLAGS="$(COMPILER_FLAGS) -static" FILES="$(FILES)" OUTPUT_FILE="$(OUTPUT_FILE)"
	$(MAKE) geneirc_compile_eshelf COMPILER="$(COMPILER)" COMPILER_FLAGS="$(COMPILER_FLAGS) -static" FILES="$(FILES)" OUTPUT_FILE="$(OUTPUT_FILE)"

mips_%: mini_loader_mips mini_loader_mipsbe
	$(MAKE) compile_all COMPILER="$(MIPS_CC)" COMPILER_FLAGS="$(CFLAGS) -BE" FILES="$(subst mips_,,$@).c $(C_FILES)" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) shellcode_$@


intel_x32_%: mini_loader_x32
	$(MAKE) compile_all COMPILER="$(X32_CC)" COMPILER_FLAGS="$(CFLAGS) -masm=intel" FILES="$(C_FILES) $(subst intel_x32_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) shellcode_$@


intel_x64_%: mini_loader_x64
	$(MAKE) compile_all COMPILER="$(X64_CC)" COMPILER_FLAGS="$(CFLAGS) -masm=intel" FILES="$(C_FILES) $(subst intel_x64_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) shellcode_$@

arm32_%: mini_loader_arm_x32
	$(MAKE) compile_all COMPILER="$(ARM_CC)" COMPILER_FLAGS="$(CFLAGS)" FILES="$(C_FILES) $(subst arm32_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) shellcode_$@

aarch64_%: mini_loader_arm_x64
	$(MAKE) compile_all COMPILER="$(AARCH64_CC)" COMPILER_FLAGS="$(CFLAGS)" FILES="$(C_FILES) $(subst aarch64_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) shellcode_$@
