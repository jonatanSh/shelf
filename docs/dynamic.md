# Dynamic loader

### Dynamic loader and function injection
you can add the dynamic loader support using
```bash
--loader-supports dynamic
```
This will increase the size of the mini loader, but will enable you to link against the loader itself
and load shellcodes yourself
in future versions it will enable you to create your own runtime resolve function
eg ...

### Function injection:
get_elf_information address (loader function) is injected while building the shellcode.
the library statically set the address of external functions.
currently, it is not exposed to the user but in future versions
support for user input for external functions will be added. 

```c
struct elf_information_struct {
    size_t elf_header_size;
    size_t loader_size;
};
struct relocation_table {
    size_t magic;
    size_t total_size;
    struct elf_information_struct elf_information;
};
void loader_main(
    int argc, 
    char ** argv, 
    char ** envp,
    size_t loader_magic,
    size_t pc);

int get_elf_information(struct relocation_table ** info);

// External defines
#define OK 1
#define ERROR -1
void main() {
   struct relocation_table * my_info;
   size_t next_shellcode_address;
   if(get_elf_information(&my_info) == ERROR) {
        return;
   }
   next_shellcode_address = my_info->base_address + my_info->total_size;
   
   // Loading and calling the concatenaited shellcode
   loader_main(
        0,
        0,
        0,
        my_info->magic,
        next_shellcode_address
   )
 
}
```

this feature is currently only enabled for:
* intel x32 shellcodes
* mips

please take a look at the elf_features test and makefile to fully understand how to use this feature
