# Dynamic loader

### Dynamic loader and function injection
you can add the dynamic loader support using
```bash
--loader-supports dynamic
```
This will increase the size of the mini loader, but will enable you to link against the mini loader
and load shellcodes or call loader functions from within the shellcode
eg ...

### Example of calling a loader function:
get_elf_information function is a loader function.
While building the shellcode if you add dynamic support
the library will link against the mini loader.
Then you can call the get_elf_information function
which is declared withing the mini loader.
#### Calling get_elf_information
[Mini loader header file](../headers/mini_loader.h)

```c
/* All external mini loader functions and structs are defined inside the mini_loader header */
#include "../headers/mini_loader.h"

void main() {
    /* Calling mini loader functions */
   struct relocation_table * my_info;
   size_t next_shellcode_address;
   if(get_elf_information(&my_info) == ERROR) {
        return;
   }
   
   /* Displaying infromation */
   printf("Got elf information: magic=%x header size = %x, loader size = %x\n",
    info->magic,
    info->elf_information.elf_header_size, 
    info->elf_information.loader_size);
 
}
```

this feature is currently only enabled for:
* intel x32
* intel x64
* mips
* arm 32

please take a look at the elf_features test and makefile to fully understand how to use this feature
