# Elf to shellcode
Convert standard elf files to standalone shellcodes.
Please read the following documentation view the examples for this project to work

## How does this work ?
The python library parses the elf and create a simple relocatable file format
Then the mini loader is inserted as the entry point of the elf the mini loader
will load the relocatable format and execute it.
There are no special requirements, the library contain the compiled
mini loaders


#### Supported architectures
* mips


## Creating a shellcode

Some compilation flags are required for this to work properly.
You must compile the binary with -fPIE and -static take a look at the provided examples below

#### Examples:

[Makefile](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/Makefile)

[Main.c](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/main.c)

#### Compiling with libc
Libc has destructors and constructors this project doesn't fully support libc.
take a look at the provided example (which uses libc) and note that some function won't work properly.

eg...


printf is using fwrite which uses the FILE * struct for stdout.
this file is opened post libc initialization (in one of the libc constructors).
__start is responsible for calling libc constructors and we don't use __start (for other reasons).
therefor you can't use printf in the shellcode, but you can implement it using snprintf and write

### Converting the elf to shellcode:

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
