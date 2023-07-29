include ./makefiles/compilers.mk
include ./makefiles/generic.mk
.PHONY: all clean shellcode_loader mini_loaders tests examples hooks

all: clean shellcode_loader mini_loaders hooks tests examples

hooks: dir_guard
	cd hooks && $(MAKE)

shellcode_loader: dir_guard
	cd shellcode_loader && $(MAKE) CC=$(MIPS_CC) ARCH=mips HOST=$(MIPS_HOST) LDFLAGS=-T./linker_scripts/$(MIPS_LINKER_SCRIPT)
	cd shellcode_loader && $(MAKE) CC=$(X32_CC) ARCH=intel_x32 HOST=$(INTEL_HOST) LDFLAGS=-T./linker_scripts/$(X32_LINKER_SCRIPT)
	cd shellcode_loader && $(MAKE) CC="$(X64_CC)" ARCH=intel_x64 HOST=$(INTEL_HOST) LDFLAGS=-T./linker_scripts/$(X64_LINKER_SCRIPT)
	cd shellcode_loader && $(MAKE) CC=$(ARM_CC) ARCH=arm32 HOST=$(ARM_HOST) LDFLAGS=-T./linker_scripts/$(ARM_LINKER_SCRIPT)
	cd shellcode_loader && $(MAKE) CC=$(AARCH64_CC) ARCH=aarch64 HOST=$(AARCH64_HOST) LDFLAGS=-T./linker_scripts/$(AARCH64_LINKER_SCRIPT)
	cd shellcode_loader && $(MAKE) CC=$(RISCV64_CC) ARCH=riscv64 HOST=$(RISCV64_HOST) LDFLAGS=-T./linker_scripts/$(RISCV64_LINKER_SCRIPT)

mini_loaders: dir_guard
	cd mini_loaders && python3 compile.py --action make clean

examples: hooks
	cd examples && $(MAKE)

tests: hooks
	cd tests && $(MAKE) clean all

clean:
	rm -rf ./outputs/*.out
