
.PHONY: all clean shellcode_loader mini_loaders examples

all: clean shellcode_loader mini_loaders examples

shellcode_loader:
	cd shellcode_loader && $(MAKE)

mini_loaders:
	cd mini_loaders && $(MAKE)

examples:
	cd examples && $(MAKE)

clean:
	rm -rf ./outputs/*.out
