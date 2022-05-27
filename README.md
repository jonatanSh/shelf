# Elf to shellcode
Convert standard elf files to standalone shellcodes.
Please read the following documentation view the examples for this project to work

## How does this work ?
The python library parses the elf and create a simple relocatable file format
Then the mini loader is inserted as the entry point of the elf the mini loader
will load the relocatable format and execute it.
There are no special requirements, the library contain the compiled
mini loaders.

This project is intended to convert elf to os independent shellcodes.
Therefor the loader never allocate memory and the shellcode format is not packed.
You can just execute it, eg ...
```c
((void (*)()) shellcode)();
```

#### Project links
[Github](https://github.com/jonatanSh/elf_to_shellcode)

[Pypi](https://pypi.org/project/elf-to-shellcode/)

#### Supported architectures
* mips
* i386 (32bit)
* i386 (64bit)
* arm (32bit)
* aarch64 (arm 64 bit)

#### Installation:
```bash
# Unfortunately only python2 is supported for now
python2 -m pip install elf_to_shellcode
```

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
python -m elf_to_shellcode binary.out mips big mipsbe.shellcode
```

### Examples:

[Makefile](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/Makefile)

[Example.c](https://github.com/jonatanSh/elf_to_shellcode/blob/master/examples/example.c)

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
from elf_to_shellcode.relocate import make_shellcode, Arches
shellcode = make_shellcode(
    binary_path="/tmp/binary.out",
    arch=Arches.MIPS_32,
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

## Specific architecture limitations

### AARCH64

arm in 64 bit mode generate adrl instruction.
These instructions are (2 ** 12) aligned (page) therfore the shellcode should be
page aligned to overcome this limitation the shellcode is padded

# Optimizations
some Compiler optimization (like -o3) may produce un-shellcodeable output.
#### Example of compiler optimization (intel x32):

```c
void * func1() {
    // ... function code
}
void * func2() {
    // ... function code
}

void * funcs[2] = {
    func1,
    func2
};

void main(int argc) {
    if(argc == 1) {
        funcs[0]();    
    }
    else {
        funcs[1]();
    }
}

```
This example actually fools -fPIE and the provided output is

```asm
cmp eax, 1 ; argc
je call_func_zero
; address is incorrect here because we are in PIC mode
call <address_of_func_one> 
call_func_zero:
    call <address_of_func_zero>
```
Address is incorrect and should be calculated as:
```asm
get_pc:
    mov eax, [esp]
    ret

call get_pc
lea eax, [eax+relative_address_of_func_1]
; then
call eax
```
