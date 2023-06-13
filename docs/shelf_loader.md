# Shelf Loader
This library is used to load [Shelf shellcodes](https://github.com/jonatanSh/shelf)

## Install
```bash
pip3 install shelf_loader
```

#### Run shelf shellcode:

```bash
python3 -m shelf_loader ./my_shellcode.out
```

#### Errors 
On errors the loader will try to resolve and disassemble the faulting address.
To do so it needs the source elf binary as argument
##### Example of an error
```bash
# This will cause error because the compiled example doesn't support no-rwx-memory
python3 -m shelf_loader ../outputs/arm32_elf_features.out.shellcode --no-rwx --source-elf ../outputs/arm32_elf_features.out
```
##### Output:
```bash
qemu-arm-static /mnt/repos/binary_relocations/shellcode_loader/shelf_loader/shelf_loader/resources/shellcode_loader_no_rwx_arm32.out ../outputs/arm32_elf_features.out.shellcode
Loading ../outputs/arm32_elf_features.out.shellcode
Shellcode size = 511472
Allocating shellcode buffer, size = 512000
Mapping new memory, size = 512000
Jumping to shellcode, address = 0xff6f4000 
info->si_addr=0xff76f00c
Faulting address: 0xff6f4404
                                              0xff6f43c4:    ldr    r3, [r3, #4]                # 0x4 0x30 0x93 0xe5
                                              0xff6f43c8:    cmp    r3, #3                      # 0x3 0x0 0x53 0xe3
                                              0xff6f43cc:    bne    #0xff6f43f4                 # 0x8 0x0 0x0 0x1a
                                              0xff6f43d0:    ldr    r3, [fp, #-0x14]            # 0x14 0x30 0x1b 0xe5
                                              0xff6f43d4:    ldr    r2, [r3]                    # 0x0 0x20 0x93 0xe5
                                              0xff6f43d8:    ldr    r3, [fp, #-0x2c]            # 0x2c 0x30 0x1b 0xe5
                                              0xff6f43dc:    ldr    r3, [r3]                    # 0x0 0x30 0x93 0xe5
                                              0xff6f43e0:    add    r3, r2, r3                  # 0x3 0x30 0x82 0xe0
                                              0xff6f43e4:    str    r3, [fp, #-0x24]            # 0x24 0x30 0xb 0xe5
                                              0xff6f43e8:    ldr    r3, [fp, #-0x24]            # 0x24 0x30 0x1b 0xe5
                                              0xff6f43ec:    str    r3, [fp, #-0x18]            # 0x18 0x30 0xb 0xe5
                                              0xff6f43f0:    b    #0xff6f43fc                   # 0x1 0x0 0x0 0xea
                                              0xff6f43f4:    mov    r3, #8                      # 0x8 0x30 0xa0 0xe3
                                              0xff6f43f8:    b    #0xff6f4460                   # 0x18 0x0 0x0 0xea
                                              0xff6f43fc:    ldr    r3, [fp, #-0x14]            # 0x14 0x30 0x1b 0xe5
                                              0xff6f4400:    ldr    r2, [fp, #-0x18]            # 0x18 0x20 0x1b 0xe5
 MLOADER:loader_handle_relocation_table ----> 0xff6f4404:    str    r2, [r3]                    # 0x0 0x20 0x83 0xe5
                                              0xff6f4408:    ldr    r3, [fp, #-8]               # 0x8 0x30 0x1b 0xe5
                                              0xff6f440c:    add    r3, r3, #0xc                # 0xc 0x30 0x83 0xe2
                                              0xff6f4410:    str    r3, [fp, #-8]               # 0x8 0x30 0xb 0xe5
                                              0xff6f4414:    ldr    r3, [fp, #-0x10]            # 0x10 0x30 0x1b 0xe5
                                              0xff6f4418:    cmp    r3, #0                      # 0x0 0x0 0x53 0xe3
                                              0xff6f441c:    beq    #0xff6f442c                 # 0x2 0x0 0x0 0xa
                                              0xff6f4420:    ldr    r3, [fp, #-0xc]             # 0xc 0x30 0x1b 0xe5
                                              0xff6f4424:    sub    r3, r3, #1                  # 0x1 0x30 0x43 0xe2
                                              0xff6f4428:    str    r3, [fp, #-0xc]             # 0xc 0x30 0xb 0xe5
                                              0xff6f442c:    ldr    r3, [fp, #-0x28]            # 0x28 0x30 0x1b 0xe5
                                              0xff6f4430:    ldr    r3, [r3, #0xc]              # 0xc 0x30 0x93 0xe5
                                              0xff6f4434:    ldr    r2, [fp, #-8]               # 0x8 0x20 0x1b 0xe5
                                              0xff6f4438:    cmp    r2, r3                      # 0x3 0x0 0x52 0xe1
```

## Debugging with the loader
by adding the following to the command line
```bash
--attach-debugger
```
you will be prompted into the loader interactive disassembler
from there you can fork into gdb using the gdb command.
inside gdb many specific commands are defined

### Commands inside gdb
#### Disassm command
The disassm command use gdb to disassemble the code where pc is pointed to.
it will also try to resolve symbols inside the shellcode and display them beside the disassembly output/


#### execute_shellcode
break on shellcode entry point

#### break_on_shellcode_main
break on shellcode main function it does this by locating the address of the shellcode main function.