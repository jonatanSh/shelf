OBJCOPY=i686-linux-gnu-objcopy
TARGETS=x32 x32_glibc x64
X32_CC=i686-linux-gnu-gcc
X64_CC=i686-linux-gnu-gcc -m64
CFLAGS=-static -nolibc -nostartfiles -g -Wno-stack-protector -masm=intel -fno-plt -fno-pic --entry=loader_main 
DEFINES=
all: $(TARGETS)

x32:
	$(X32_CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_x32.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x32.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x32.shellcode

x32_glibc:
	$(X32_CC) $(CFLAGS) -DSUPPORT_START_FILES ../generic_loader.c -o ../../outputs/mini_loader_x32_glibc.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x32_glibc.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x32_glibc.shellcode


x64:
	$(X64_CC) $(CFLAGS) $(DEFINES) ../generic_loader.c -o ../../outputs/mini_loader_x64.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_x64.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_x64.shellcode
