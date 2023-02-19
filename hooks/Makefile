SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/../makefiles/compilers.mk

CFLAGS=-fno-stack-protector -g -static -Wno-stack-protector
CFLAGS+=-nolibc --entry=hook_main -nostartfiles -fno-plt -fno-pic
OUTPUT_DIRECTORY=../outputs/
TARGETS=mips_simple_hello_hook intel_x32_simple_hello_hook intel_x64_simple_hello_hook
TARGETS+=arm_simple_hello_hook aarch64_simple_hello_hook


all: $(TARGETS)

mips_%:
	$(MIPS_CC) $(CFLAGS) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(MIPS_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

intel_x32_%:
	$(X32_CC) $(CFLAGS) -masm=intel -static -BE $(subst intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X32_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

intel_x64_%:
	$(X64_CC) $(CFLAGS) -masm=intel -static -BE $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

arm_%:
	$(X64_CC) $(CFLAGS) -masm=intel -static -BE $(subst arm_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

aarch64_%:
	$(X64_CC) $(CFLAGS) -masm=intel -static -BE $(subst aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook