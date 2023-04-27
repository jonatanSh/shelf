#include <asm/unistd.h>
#include "../osals/linux/syscalls/syscalls.h"
#include "../mini_loaders/generic_loader.h"

struct hook_attributes {
    size_t message_length;
    char message[];
};

// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main(void * table, struct hook_attributes * hook) {
    long long _out;
    ARCH_GET_FUNCTION_OUT();
    ARCH_FUNCTION_ENTER();
	my_syscall3(__NR_write, 1, hook->message, hook->message_length);
    ARCH_RETURN(_out);
}