#include <asm/unistd.h>
#include "../osals/linux/syscalls/syscalls.h"
#include "../mini_loaders/generic_loader.h"

struct hook_attributes {
    size_t message_length;
    char message[];
};

// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main(void * base_address, void * table, struct hook_attributes * hook) {
    long long _out;
    ARCH_GET_FUNCTION_OUT();
    size_t return_address;
    ARCH_FUNCTION_ENTER(&return_address);
	my_syscall3(__NR_write, 1, hook->message, hook->message_length);
    ARCH_FUNCTION_EXIT(return_address);
    ARCH_RETURN(_out);
}