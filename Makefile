include ./makefiles/compilers.mk
.PHONY: all clean shellcode_loader mini_loaders examples
EXTRA_FLAGS=-static

all: clean shellcode_loader mini_loaders examples

shellcode_loader_m1:
	cd shellcode_loader && $(MAKE) CC=gcc ARCH=m1
	codesign --sign "-" --verbose=4 --options=runtime --entitlements=./mac_entitlements.plist ./outputs/shellcode_loader_m1.out

shellcode_loader:
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips EXTRA_FLAGS=$(EXTRA_FLAGS)
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32 EXTRA_FLAGS=$(EXTRA_FLAGS)
	cd shellcode_loader && $(MAKE) CC="$(X64_CC)" ARCH=intel_x64 EXTRA_FLAGS=$(EXTRA_FLAGS)
	cd shellcode_loader && $(MAKE) CC=$(ARM_CC) ARCH=arm32 EXTRA_FLAGS=$(EXTRA_FLAGS)
	cd shellcode_loader && $(MAKE) CC=$(AARCH64_CC) ARCH=aarch64 EXTRA_FLAGS=$(EXTRA_FLAGS)
mini_loaders:
	cd mini_loaders && python compile.py release

examples:
	cd examples && $(MAKE)

clean:
	rm -rf ./outputs/*.out
