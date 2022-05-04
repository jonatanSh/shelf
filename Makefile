MIPS_CC=mips-linux-gnu-gcc
X32_CC=i686-linux-gnu-gcc
X64_CC="gcc -m64"

.PHONY: all clean shellcode_loader mini_loaders examples

all: clean shellcode_loader mini_loaders examples

shellcode_loader:
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32
	cd shellcode_loader && $(MAKE) CC=$(X64_CC) ARCH=intel_x64

mini_loaders:
	cd mini_loaders && $(MAKE)

examples:
	cd examples && $(MAKE)

clean:
	rm -rf ./outputs/*.out
