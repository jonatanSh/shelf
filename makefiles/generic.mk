CFLAGS+=-fno-stack-protector -fPIE -fpic
CFLAGS+=-nostartfiles --entry=main
EXCLUDE_HELLO_HOOK?=
EXCLUDE_ESHELF?=
EXCLUDE_DYNAMIC?=
SHELF_ADDITIONAL_ARGS?=
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/compilers.mk

ifeq ($(MINI_LOADER_DEBUG),1)
	MINI_LOADER_ARGS=--debug
else
	MINI_LOADER_ARGS=
endif
dir_guard:
	mkdir -p $(SELF_DIR)/../outputs

ifeq ($(VERBOSE), 1)
	SHELF_ADDITIONAL_ARGS=--verbose
endif
SHELF_ARGS=--relocate-opcodes

mini_loader_%: dir_guard
	@if [ -z $(EXCLUDE_LOADER) ]; then\
		cd $(SELF_DIR)/../mini_loaders && python3 compile.py --action make --arch $(subst mini_loader_,,$@) $(MINI_LOADER_ARGS);\
	fi
shellcode: dir_guard
	python3 -m shelf $(SHELF_ARGS) --input $(OUTPUT_DIRECTORY)/$(INPUT_FILE) --output $(OUTPUT_DIRECTORY)/$(INPUT_FILE)$(NAME_ADD).shellcode $(SUPPORT_ARG) $(SHELF_ADDITIONAL_ARGS)
	@if [ -z $(EXCLUDE_HELLO_HOOK) ]; then\
		python3 -m shelf $(SHELF_ARGS) --input $(OUTPUT_DIRECTORY)/$(INPUT_FILE) --output $(OUTPUT_DIRECTORY)/$(INPUT_FILE).hooks$(NAME_ADD).shellcode --loader-supports hooks $(SHELF_ADDITIONAL_ARGS) $(SUPPORT) --hooks-configuration ../hook_configurations/simple_hello_hook.py;\
	fi
	@if [ -z $(EXCLUDE_ESHELF) ]; then\
		python3 -m shelf $(SHELF_ARGS) --input $(OUTPUT_DIRECTORY)/$(INPUT_FILE).eshelf --output $(OUTPUT_DIRECTORY)/$(INPUT_FILE).eshelf$(NAME_ADD).shellcode --output-format eshelf $(SUPPORT_ARG) $(SHELF_ADDITIONAL_ARGS);\
	fi
	@if [ -z $(EXCLUDE_DYNAMIC) ]; then\
		python3 -m shelf $(SHELF_ARGS) --input $(OUTPUT_DIRECTORY)/$(INPUT_FILE) --output $(OUTPUT_DIRECTORY)/$(INPUT_FILE).rwx_bypass$(NAME_ADD).shellcode --mitigation-bypass rwx $(SUPPORT_ARG) $(SHELF_ADDITIONAL_ARGS);\
	fi

all_shellcodes:
	$(MAKE) shellcode INPUT_FILE="$(INPUT_FILE)"
	@if [ -z $(EXCLUDE_DYNAMIC) ]; then\
		$(MAKE) shellcode INPUT_FILE="$(INPUT_FILE)" NAME_ADD=".dynamic" SUPPORT_ARG="--loader-supports dynamic" SUPPORT="dynamic";\
	fi
geneirc_compile:
	$(COMPILER) $(COMPILER_FLAGS) $(FILES) -o $(OUTPUT_FILE)

geneirc_compile_eshelf:
	$(COMPILER) $(COMPILER_FLAGS) $(FILES) -o $(OUTPUT_FILE).eshelf -DESHELF

generic_osal_dynamic:
	$(COMPILER) $(COMPILER_FLAGS) -DOSAL_LIBC $(OSAL_FILES) -shared -nolibc -lm -lc -lgcc -lc $(FILES) -o $(OUTPUT_FILE).dynamic -DDYNAMIC_SUPPORT

compile_all:
	$(MAKE) geneirc_compile COMPILER="$(COMPILER)" COMPILER_FLAGS="$(COMPILER_FLAGS) $(STATIC_FLAGS)" FILES="$(C_FILES) $(FILES)" OUTPUT_FILE="$(OUTPUT_FILE)"
	@if [ -z $(EXCLUDE_ESHELF) ]; then\
		$(MAKE) geneirc_compile_eshelf COMPILER="$(COMPILER)" COMPILER_FLAGS="$(COMPILER_FLAGS) $(STATIC_FLAGS)" FILES="$(C_FILES) $(FILES)" OUTPUT_FILE="$(OUTPUT_FILE)";\
	fi
	@if [ -z $(EXCLUDE_DYNAMIC) ]; then\
		$(MAKE) generic_osal_dynamic COMPILER="$(COMPILER)" COMPILER_FLAGS="$(COMPILER_FLAGS) $(STATIC_FLAGS)" FILES="$(C_FILES) $(FILES)" OUTPUT_FILE="$(OUTPUT_FILE)";\
	fi

mips_%: mini_loader_mips mini_loader_mipsbe
	$(MAKE) compile_all COMPILER="$(MIPS_CC)" COMPILER_FLAGS="$(CFLAGS) -BE" STATIC_FLAGS="-static" FILES="$(subst mips_,,$@).c"  OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"


intel_x32_%: mini_loader_x32
	$(MAKE) compile_all COMPILER="$(X32_CC)" COMPILER_FLAGS="$(CFLAGS) -masm=intel" STATIC_FLAGS="-static" FILES="$(subst intel_x32_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"


intel_x64_%: mini_loader_x64
	$(MAKE) compile_all COMPILER="$(X64_CC)" COMPILER_FLAGS="$(CFLAGS) -masm=intel" STATIC_FLAGS="-static" FILES="$(subst intel_x64_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"

arm32_%: mini_loader_arm_x32
	$(MAKE) compile_all COMPILER="$(ARM_CC)" COMPILER_FLAGS="$(CFLAGS)" STATIC_FLAGS="-static" FILES="$(subst arm32_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"

aarch64_%: mini_loader_arm_x64
	$(MAKE) compile_all COMPILER="$(AARCH64_CC)" COMPILER_FLAGS="$(CFLAGS)" STATIC_FLAGS="-static" FILES="$(subst aarch64_,,$@).c" OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"

riscv64_%: mini_loader_riscv64
	$(MAKE) compile_all COMPILER="$(RISCV64_CC)" COMPILER_FLAGS="$(CFLAGS)" STATIC_FLAGS="-static" FILES="$(subst riscv64_,,$@).c"  OUTPUT_FILE="$(OUTPUT_DIRECTORY)$@.out"
	$(MAKE) all_shellcodes INPUT_FILE="$@.out"

