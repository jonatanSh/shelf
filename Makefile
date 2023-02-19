include ./makefiles/compilers.mk
.PHONY: all clean shellcode_loader mini_loaders tests examples hooks

all: clean shellcode_loader mini_loaders hooks tests examples

hooks:
	cd hooks && $(MAKE)

shellcode_loader:
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32
	cd shellcode_loader && $(MAKE) CC="$(X64_CC)" ARCH=intel_x64
	cd shellcode_loader && $(MAKE) CC=$(ARM_CC) ARCH=arm32
	cd shellcode_loader && $(MAKE) CC=$(AARCH64_CC) ARCH=aarch64
mini_loaders:
	cd mini_loaders && python compile.py release

examples: hooks
	cd examples && $(MAKE)

test: hooks
	cd test && $(MAKE)

clean:
	rm -rf ./outputs/*.out
