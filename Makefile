include ./makefiles/compilers.mk
include ./makefiles/generic.mk
.PHONY: all clean shellcode_loader mini_loaders tests examples hooks

all: clean shellcode_loader mini_loaders hooks tests examples

hooks: dir_guard
	cd hooks && $(MAKE)

shellcode_loader: dir_guard
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32
	cd shellcode_loader && $(MAKE) CC="$(X64_CC)" ARCH=intel_x64
	cd shellcode_loader && $(MAKE) CC=$(ARM_CC) ARCH=arm32
	cd shellcode_loader && $(MAKE) CC=$(AARCH64_CC) ARCH=aarch64
	cd shellcode_loader && $(MAKE) CC=$(RISCV64_CC) ARCH=riscv64

mini_loaders: dir_guard
	cd mini_loaders && python compile.py --action make clean

examples: hooks
	cd examples && $(MAKE)

tests: hooks
	cd tests && $(MAKE) clean all

clean:
	rm -rf ./outputs/*.out
