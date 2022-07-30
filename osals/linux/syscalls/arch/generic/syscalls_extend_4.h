#ifndef SYSCALLS_EXTEND_HEADER_FOUR
#define SYSCALLS_EXTEND_HEADER_FOUR

#include "syscalls_extend_3.h"

#define my_syscall4(num, arg1, arg2, arg3, arg4)    \
({													\
	my_syscall5(num, arg1, arg2, arg3, arg4, NULL);	\
})
#endif //SYSCALLS_EXTEND_HEADER_FOUR