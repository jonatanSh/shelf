# Shelf - Shellcode ELF convert elf to shellcode
Convert standard elf files to standalone shellcodes.
Please read the following documentation and view the examples for this project to work properly

#### Project links
[Github](https://github.com/jonatanSh/shelf)

[Pypi](https://pypi.org/project/py_shelf/)

#### Supported architectures
* mips
* i386 (intel x32)
* x86_64 (intel x64)
* arm (32bit)
* aarch64 (arm 64 bit)
* RISC-V rv64

#### Installation:
```bash
pip install py_shelf
```
###### Python version support
* python3


## How does this work ?
The python library parses the elf and create a simple relocatable file format called shelf (shellcode elf).

The mini loader is inserted as the entry point for shelf.

the mini loader will load and relocate the shelf then it will execute it.
There are no special requirements, the library contain the compiled
mini loaders and resources.

The diagram below explain the format (Only work in browsers)

```mermaid
  classDiagram
    ShellcodeEntryPoint --|> MiniLoader
    ShellcodeEntryPoint: Shellcode containing pre mini loader logic
    MiniLoader --|> Relocation table
    MiniLoader: Contain all the logic for parsing the relocation table
    MiniLoader: fully os independent
    Relocation table --|> HOOKS Optional
    Relocation table : Contain table required for shellcode runtime relocation
    HOOKS Optional --|> SHELF
    HOOKS Optional: Read more about hooks in the documentation below
    HOOKS Optional: This section is optional and only exists if hooks are used
    SHELF: Shellcode elf - This is the compiled binary we convert into shellcode
    SHELF: This binary is stripped into only opcodes
    SHELF: fully relocatable using the relocation table
```

This project is intended to convert elf to os independent shellcodes.
Therefor the loader never allocate memory and the shellcode format is not packed.
You can just execute it, eg ...
```c
((void (*)()) shellcode)();
```
* note that __libc_start_main perform syscalls
therefor if you want your shellcode to be fully os independent you must compile with -nostartfiles
* Shelf by default expects RWX (Read Write Execute) memory shelf can run in [RX environments (Read Execute) Click the link to read more](docs/mitigation_bypass.md)

follow the examples below

## Creating a shellcode

Some compilation flags are required for this to work properly.
You must compile the binary with -fPIE and -static take a look at the provided examples below
(makefile).

shellcode is a stripped binary with no symbols and no elf information only opcodes, in order 
to make the shellcode this library require a binary with elf information.
so make sure you are not stripping the binary before using this library

simplified make command for mips big endian

```c
gcc example.c -fno-stack-protector -fPIE -fpic -static -nostartfiles --entry=main -o binary.out
python -m shelf --input binary.out                                     
```

### Examples:

[Makefile](https://github.com/jonatanSh/shelf/blob/master/examples/Makefile)

[Example.c](https://github.com/jonatanSh/shelf/blob/master/examples/example.c)



### Testing your shellcode
You can use the provided shellcode [Loader](https://github.com/jonatanSh/shelf/tree/master/shellcode_loader)
to test you shellcodes

```bash
qemu-mips ./shellcode_loader ./myshellcode.out
```

#### Using the shelf loader library
it is advised to use the shelf loader library to tests your shellcode
here you can read more about it: [Shelf loader documentation](https://github.com/jonatanSh/shelf/tree/master/docs/shelf_loader.md)



## Advanced concepts and features
for following links only work on the github page
* [Opcode relocations](docs/opcodes_relocation.md)
* [Compiling with libc](docs/libc.md)
* [Dynamic shellcode](docs/dynamic.md)
* [Hooking the mini loader](docs/hooks.md)
* [Mitigation bypass](docs/mitigation_bypass.md)
* [Optimizations](docs/optimizations.md)
* [Output formats](docs/output_formats.md)
* [Python api](docs/py_api.md)
* [Development](docs/develop.md)
* [Specific architecture limitations](docs/speific_arch_limitations.md)