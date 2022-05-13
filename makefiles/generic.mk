CFLAGS+=-fno-stack-protector -fPIE -fpic -static
TARGETS+=mips intel_x32 intel_x64
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/compilers.mk

all: $(TARGETS)

mips:
	$(MIPS_CC) $(CFLAGS) -BE main.c -o ../outputs/$(OUTPUT_FORMAT)_mipsbe.out

intel_x32:
	$(X32_CC) $(CFLAGS) main.c -o ../outputs/$(OUTPUT_FORMAT)_intel_x32.out

intel_x64:
	$(X64_CC) $(CFLAGS) main.c -o ../outputs/$(OUTPUT_FORMAT)_intel_x64.out
