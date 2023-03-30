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
	size_t relative_address;
};
#define PAGE_SIZE 4096


// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main(void * table, 
	size_t * number_of_attributes, 
	void * addr,
	struct addresses * addresses
	) {
	long long _out;
	size_t protection = 0x0;
	size_t return_address;
	ARCH_GET_FUNCTION_OUT();
	ARCH_FUNCTION_ENTER(&return_address);
	void * hook_start = (void*)(number_of_attributes)+(1 * sizeof(void*));
	for(size_t i = 0; i < *number_of_attributes; i++) {
		void * hook_add;
		struct hook_attributes * hook = (struct hook_attributes *)(hook_start + i*sizeof(struct hook));
		if(hook->relative_address) {
			hook_add = ((void*)hook->relative_address + addresses->base_address);
		}
		else {
			hook_add = addr;
		}
		if(hook->protection & _PROT_READ) {
			protection |= PROT_READ; 
		}
		if(hook->protection & _PROT_WRITE) {
			protection |= PROT_WRITE; 
		}
		if(hook->protection & _PROT_EXEC) {
			protection |= PROT_EXEC; 
		}
		while((size_t)hook_add % PAGE_SIZE) {
			hook_add--;
		}
		my_syscall3(__NR_mprotect, hook_add, hook->mmap_size, protection);
	}

	ARCH_FUNCTION_EXIT(return_address);
	ARCH_RETURN(_out);
}