# Elf to shellcode
Convert standard elf files to standalone shellcodes

# How does this work ?
The python library parses the elf and create a simple relocatable file format
Then the mini loader is inserted as the entry point of the elf the mini loader
will load the relocatable format and execute it.
There are no special requirements, the library contain the compiled
mini loaders


# Supported architectures
* mips


# Creating a shellcode

Some compilation flags are required for this to work properly.

#### Examples:

[Makefile](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/Makefile)

[Main.c](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/main.c)

### How to make a shellcode from an elf:

```python
from elf_to_shellcode.relocate import make_shellcode

shellcode = make_shellcode(
    binary_path="/tmp/binary.out",
    arch="mips",
    endian="big"
)

with open("myshellcode.out", 'wb') as fp:
    fp.write(shellcode)
```

### Testing your shellcode
You can use the provided shellcode
[Loader](https://github.com/jonatanSh/elf_to_shellcode/tree/master/shellcode_loader)
to test you shellcodes

```bash
qemu-mips ./shellcode_loader ./myshellcode.out
```

### Output example
```bash
Shellcode size = 66620
Allocating shellcode buffer, size = 69632
Mapping new memory, size = 69632
Jumping to shellcode, address = 0x7f7ee000
Hello from shellcode !
```
