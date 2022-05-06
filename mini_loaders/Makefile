TARGETS=mips x32 x64

.PHONY: all $(TARGETS)
all: $(TARGETS)

mips:
	cd mips && make

x32:
	cd intel && make x32

x64:
	cd intel && make x64