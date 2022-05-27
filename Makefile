include ./makefiles/compilers.mk
.PHONY: all clean shellcode_loader mini_loaders examples

all: clean shellcode_loader mini_loaders examples

shellcode_loader:
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32
	cd shellcode_loader && $(MAKE) CC="$(X64_CC)" ARCH=intel_x64
	cd shellcode_loader && $(MAKE) CC=$(ARM_CC) ARCH=arm_32
	cd shellcode_loader && $(MAKE) CC=$(AARCH64_CC) ARCH=aarch64
mini_loaders:
	cd mini_loaders && $(MAKE)

examples:
	cd examples && $(MAKE)

clean:
	rm -rf ./outputs/*.out
