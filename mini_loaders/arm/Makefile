OBJCOPY=arm-linux-gnueabi-objcopy
OBJCOPY_64=aarch64-linux-gnu-objcopy
TARGETS=arm32 arm64 arm32_dynamic arm64_dynamic
X32_CC=arm-linux-gnueabi-gcc
x64_CC=aarch64-linux-gnu-gcc
CFLAGS=--entry=loader_main -static -nolibc -nostartfiles -g -Wno-stack-protector -fno-plt -fno-pic
RESOURCES=../../elf_to_shellcode/elf_to_shellcode/resources/

all: $(TARGETS)

arm32:
	$(X32_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x32.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_arm_x32.out $(RESOURCES)mini_loader_arm_x32.shellcode
	readelf -S ../../outputs/mini_loader_arm_x32.out > $(RESOURCES)mini_loader_arm_x32.shellcode.symbols

arm64:
	$(x64_CC) $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x64.out
	$(OBJCOPY_64) -j .text -O binary ../../outputs/mini_loader_arm_x64.out $(RESOURCES)mini_loader_arm_x64.shellcode
	readelf -S ../../outputs/mini_loader_arm_x64.out > $(RESOURCES)mini_loader_arm_x64.shellcode.symbols

arm32_dynamic:
	$(X32_CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x32_dynamic.out
	$(OBJCOPY) -j .text -O binary ../../outputs/mini_loader_arm_x32_dynamic.out $(RESOURCES)mini_loader_arm_x32_dynamic.shellcode
	readelf -S ../../outputs/mini_loader_arm_x32_dynamic.out > $(RESOURCES)mini_loader_arm_x32_dynamic.shellcode.symbols

arm64_dynamic:
	$(x64_CC) -DSUPPORT_DYNAMIC_LOADER $(CFLAGS) ../generic_loader.c -o ../../outputs/mini_loader_arm_x64_dynamic.out
	$(OBJCOPY_64) -j .text -O binary ../../outputs/mini_loader_arm_x64_dynamic.out $(RESOURCES)mini_loader_arm_x64_dynamic.shellcode
	readelf -S ../../outputs/mini_loader_arm_x64_dynamic.out > $(RESOURCES)mini_loader_arm_x64_dynamic.shellcode.symbols
