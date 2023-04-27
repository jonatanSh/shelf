SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/../makefiles/compilers.mk

CFLAGS=-fno-stack-protector -g -static -Wno-stack-protector
CFLAGS+=-nolibc --entry=hook_main -nostartfiles -fno-plt
CFLAGS+=-DSUPPORT_HOOKS
OUTPUT_DIRECTORY=../outputs/
RESORUCE_DIRECTORY=../shelf/resources/
TARGETS=mips_simple_hello_hook intel_x32_simple_hello_hook intel_x64_simple_hello_hook
TARGETS+=arm32_simple_hello_hook aarch64_simple_hello_hook riscv64_simple_hello_hook

MEM_CHANGE_PROTECTION_HOOK+=resource_mips_mem_change_protection_hook resource_intel_x32_mem_change_protection_hook resource_intel_x64_mem_change_protection_hook
MEM_CHANGE_PROTECTION_HOOK+=resource_arm32_mem_change_protection_hook resource_aarch64_mem_change_protection_hook resource_riscv64_mem_change_protection_hook

TARGETS+=$(MEM_CHANGE_PROTECTION_HOOK)

all: $(TARGETS)

mips_%:
	$(MIPS_CC) $(CFLAGS) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(MIPS_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

intel_x32_%:
	$(X32_CC) $(CFLAGS) -masm=intel -static $(subst intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X32_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

intel_x64_%:
	$(X64_CC) $(CFLAGS) -masm=intel -static $(subst intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

arm32_%:
	$(ARM_CC) $(CFLAGS) -static $(subst arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(ARM_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

aarch64_%:
	$(AARCH64_CC) $(CFLAGS) -fpic -static $(subst aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(AARCH64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

riscv64_%:
	$(RISCV64_CC) $(CFLAGS) -fpic -static $(subst riscv64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(RISCV64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(OUTPUT_DIRECTORY)$@.hook

resource_mips_%:
	$(MIPS_CC) $(CFLAGS) -static -BE $(subst resource_mips_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(MIPS_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook

resource_intel_x32_%:
	$(X32_CC) $(CFLAGS) -masm=intel -static $(subst resource_intel_x32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X32_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook

resource_intel_x64_%:
	$(X64_CC) $(CFLAGS) -masm=intel -static $(subst resource_intel_x64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(X64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook

resource_arm32_%:
	$(ARM_CC) $(CFLAGS) -static $(subst resource_arm32_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(ARM_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook

resource_aarch64_%:
	$(AARCH64_CC) $(CFLAGS) -fpic -static $(subst resource_aarch64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(AARCH64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook

resource_riscv64_%:
	$(RISCV64_CC) $(CFLAGS) -fpic -static $(subst resource_riscv64_,,$@).c -o $(OUTPUT_DIRECTORY)$@.out
	$(RISCV64_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$@.out $(RESORUCE_DIRECTORY)$@.hook