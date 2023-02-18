SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/../../makefiles/compilers.mk
include $(SELF_DIR)/../../makefiles/osal.mk

CFLAGS=-fno-stack-protector -g -static -Wno-stack-protector
CFLAGS+=-nolibc --entry=hook_main -nostartfiles -fno-plt -fno-pic
OUTPUT_DIRECTORY=../../outputs/
TARGETS=osal_mips_simple_hello_hook


all: $(TARGETS)

osal_mips_%:
	$(MIPS_CC) -DHOOK_OSAL $(OSAL_DEBUG_PACKAGE) $(CFLAGS) -static -BE $(subst osal_mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst osal_mips_,,$@)_mipsbe.out
	$(MIPS_OBJCOPY) -j .text -O binary $(OUTPUT_DIRECTORY)$(subst osal_mips_,,$@)_mipsbe.out $(OUTPUT_DIRECTORY)$(subst osal_mips_,,$@)_mipsbe.hook

mips_%:
	$(MIPS_CC) $(CFLAGS) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out
	$(MIPS_OBJCOPY) -j .text -O binary $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.hook