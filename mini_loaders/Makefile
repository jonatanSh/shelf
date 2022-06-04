TARGETS=mips x32 x32_glibc x64 arm32 aarch64

.PHONY: all $(TARGETS)
all: $(TARGETS)

mips:
	cd mips && make

x32:
	cd intel && make x32

x32_glibc:
	cd intel && make x32_glibc
	
x64:
	cd intel && make x64

arm32:
	cd arm && make arm32
aarch64:
	cd arm && make arm64