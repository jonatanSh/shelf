CC=mips-linux-gnu-gcc
OBJCOPY=mips-linux-gnu-objcopy
CFLAGS=-g -static -Wno-stack-protector -nolibc -nostartfiles --entry=loader_main
DEFINES=
TARGETS=mips mipsbe mips_dynamic mipsbe_dynamic
RESOURCES=../../elf_to_shellcode/elf_to_shellcode/resources/
all: $(TARGETS)

mips:
	$(CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out $(RESOURCES)mini_loader_mips.shellcode
	readelf -s ../../outputs/mini_loader_mips.out > $(RESOURCES)mini_loader_mips.shellcode.symbols
mipsbe:
	$(CC) $(CFLAGS) $(DEFINES) -BE ../generic_loader.c -o ../../outputs/mini_loader_mips_be.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out $(RESOURCES)mini_loader_mipsbe.shellcode
	readelf -s ../../outputs/mini_loader_mips.out > $(RESOURCES)mini_loader_mipsbe.shellcode.symbols
	
mips_dynamic:
	$(CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips_dynamic.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips_dynamic.out $(RESOURCES)mini_loader_mips_dynamic.shellcode
	readelf -s ../../outputs/mini_loader_mips.out > $(RESOURCES)mini_loader_mips_dynamic.shellcode.symbols

mipsbe_dynamic:
	$(CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) $(DEFINES) -BE ../generic_loader.c -o ../../outputs/mini_loader_mipsbe_dynamic.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mipsbe_dynamic.out $(RESOURCES)mini_loader_mipsbe_dynamic.shellcode
	readelf -s ../../outputs/mini_loader_mips.out > $(RESOURCES)mini_loader_mipsbe_dynamic.shellcode.symbols
	