# Compiling with libc
Libc has destructors and constructors only some architectures fully support libc.
take a look at the provided example (which uses libc) and note that some function won't work properly in some architectures.

eg...

printf is using fwrite which uses the FILE * struct for stdout.
this file is opened post libc initialization (in one of the libc constructors).
__libc_start_main is responsible for calling libc constructors and we don't support __start in all architecutres (for other reasons).
therefor you can't use printf in the shellcode, but you can implement it using snprintf and write

### Architectures that partially support libc:

* mips
* i386 (32bit)
* i386 (64bit)
* arm (32bit)
* aarch64 (arm 64 bit)

### Architectures that fully support libc:

* None