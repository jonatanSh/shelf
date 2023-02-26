#include <asm/unistd.h>
#include "../osals/linux/syscalls/syscalls.h"
#include "../mini_loaders/loader_generic.h"

// Must be the first data in the binary !
__attribute__((section( ".init" )))
void hook_main() {
    size_t return_address;
    size_t rt = 0x0;
    ARCH_FUNCTION_ENTER(&return_address);
    char buffer[18];
    buffer[0] = 'h';
    buffer[1] = 'e';
    buffer[2] = 'l';
    buffer[3] = 'l';
    buffer[4] = 'o';
    buffer[5] = ' ';
    buffer[6] = 'f';
    buffer[7] = 'r';
    buffer[8] = 'o';
    buffer[9] = 'm';
    buffer[10] = ' ';
    buffer[11] = 'h';
    buffer[12] = 'o';
    buffer[13] = 'o';
    buffer[14] = 'k';
    buffer[15] = '!';
    buffer[16] = '\n';
    buffer[17] = 0x0;
	my_syscall3(__NR_write, 1, buffer, 17);
    ARCH_FUNCTION_EXIT(return_address);
    ARCH_RETURN(rt);
}