# Opcode relocations
Supported in:
* x86 32 bit
* riscv64 bit

### Usage
Add the following to the command
```bash
--relocate-opcodes
```

# About

Some compilers don't fully support PIC binaries when compiling with libc.

They generate position-dependent code (will be referred as PDC).

The opcode relocations feature reloctae the PDC stubs.

For the supported architectures the library will try to detect PDC and warn
the user if a PDC was found.

### Warning
The library try to do its best to relocate PDC stubs.

But in some cases a program can fool the library to relocate other stubs.

For example if the shellcode use a libc function located at 0x8000000

and the user set some variable to 0x8000000 eg:

```c
# Located at 0x8000000
void my_libc_function() { };

void main() {
    int my_cool_var = 0x8000000;
}
```

In the following program the library can accidentally relocate

my_cool_var to point to my_libc_function.

This depends on the architecture, but generally

the library first check if the PDC is within the shellcode virtual range.

Note that the library doesn't know where the shellcode is loaded to.

Therefor, it only checks if this function or variable is declared within the shellcode.
### PDC in architectures
#### PDC in x86
Available PDC stubs in x86 are:

```asm
mov $reg, <value>
```
Value is then checked against the binary symbols and if a correlative symbol
is found this opcode will be relocated at load time by the mini loader.

#### PDC in riscv64
Riscv64 PDCs are harder to detect, the glibc compiler generate a lui,ld stub:

```asm
    lui	a4,0x72
    ld	a1,-1992(a4)
```
This PDC replaces the calculation with the correlating aiupc lui instruction
eg ...

```asm
    aiupc a4,0x23
    ld	a1,-300(a4)
```