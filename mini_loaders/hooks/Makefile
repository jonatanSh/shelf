SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/../../makefiles/compilers.mk

CFLAGS=-fno-stack-protector -g -static -Wno-stack-protector
CFLAGS+=-nolibc --entry=hook_main -nostartfiles -fno-plt -fno-pic
OUTPUT_DIRECTORY=../../outputs/
TARGETS=mips_simple_hello_hook


all: $(TARGETS)

mips_%:
	$(MIPS_CC) $(CFLAGS) -static -BE $(subst mips_,,$@).c -o $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out
	$(MIPS_OBJCOPY) -j .init -j .text -O binary $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.out $(OUTPUT_DIRECTORY)$(subst mips_,,$@)_mipsbe.hook