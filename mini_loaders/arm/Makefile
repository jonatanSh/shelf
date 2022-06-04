OBJCOPY=arm-linux-gnueabi-objcopy
OBJCOPY_64=aarch64-linux-gnu-objcopy
TARGETS=arm32 arm64
X32_CC=arm-linux-gnueabi-gcc
x64_CC=aarch64-linux-gnu-gcc
CFLAGS=--entry=loader_main -static -nolibc -nostartfiles -g -Wno-stack-protector -fno-plt -fno-pic

all: $(TARGETS)

arm32:
	$(X32_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x32.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_arm_x32.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_arm_x32.shellcode

arm64:
	$(x64_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x64.out
	$(OBJCOPY_64) -j .text -O binary ../../outputs/mini_loader_arm_x64.out ../../elf_to_shellcode/elf_to_shellcode/resources/mini_loader_arm_x64.shellcode
