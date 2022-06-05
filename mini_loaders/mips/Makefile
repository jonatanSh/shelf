CC=mips-linux-gnu-gcc
OBJCOPY=mips-linux-gnu-objcopy
CFLAGS=-g -static -Wno-stack-protector -nolibc -nostartfiles --entry=loader_main
DEFINES=
TARGETS=mips mipsbe mips_dynamic mipsbe_dynamic
all: $(TARGETS)

mips:
	$(CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mips.shellcode

mipsbe:
	$(CC) $(CFLAGS) $(DEFINES) -BE ../generic_loader.c -o ../../outputs/mini_loader_mips_be.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mipsbe.shellcode
	
mips_dynamic:
	$(CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_mips_dynamic.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mips_dynamic.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mips_dynamic.shellcode

mipsbe_dynamic:
	$(CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) $(DEFINES) -BE ../generic_loader.c -o ../../outputs/mini_loader_mipsbe_dynamic.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_mipsbe_dynamic.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_mipsbe_dynamic.shellcode
	