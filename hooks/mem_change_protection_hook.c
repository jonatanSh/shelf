#include <asm/unistd.h>
#include <sys/mman.h>
#include "../osals/linux/syscalls/syscalls.h"
#include "../mini_loaders/generic_loader.h"

#define _PROT_READ (2 << 0)
#define _PROT_WRITE (2 << 1)
#define _PROT_EXEC (2 << 2)

struct hook_attributes {
    size_t protection;
    size_t mmap_size;
};
#define PAGE_SIZE 4096


// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main(void * table, struct hook_attributes * hook, void * addr) {
    long long _out;
    size_t protection = 0x0;
    size_t return_address;
    ARCH_GET_FUNCTION_OUT();
    ARCH_FUNCTION_ENTER(&return_address);
    if(hook->protection & _PROT_READ) {
        protection |= PROT_READ; 
    }
    if(hook->protection & _PROT_WRITE) {
        protection |= PROT_WRITE; 
    }
    if(hook->protection & _PROT_EXEC) {
        protection |= PROT_EXEC; 
    }
    while((size_t)addr % PAGE_SIZE) {
        addr--;
    }
	my_syscall3(__NR_mprotect, addr, hook->mmap_size, protection);
    
    ARCH_FUNCTION_EXIT(return_address);
    ARCH_RETURN(_out);
}