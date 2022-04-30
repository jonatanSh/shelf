
.PHONY: all clean shellcode_loader mini_loaders

all: clean shellcode_loader mini_loaders

shellcode_loader:
	cd shellcode_loader && $(MAKE)

mini_loaders:
	cd mini_loaders && $(MAKE)

clean:
	rm -rf ./outputs/*.out
