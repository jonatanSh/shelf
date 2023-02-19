#include <asm/unistd.h>
#include "../../osals/linux/syscalls/syscalls.h"
#include "../loader_generic.h"

// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main() {
    char buffer[8];
    buffer[0] = 'h';
    buffer[1] = 'e';
    buffer[2] = 'l';
    buffer[3] = 'l';
    buffer[4] = 'o';
    buffer[5] = '!';
    buffer[6] = '\n';
    buffer[7] = 0x0;
	my_syscall3(__NR_write, 1, buffer, 7);
    ARCH_FUNCTION_EXIT(0);
}