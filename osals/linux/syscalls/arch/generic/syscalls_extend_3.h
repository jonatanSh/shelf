#ifndef SYSCALLS_EXTEND_HEADER_THREE
#define SYSCALLS_EXTEND_HEADER_THREE

#include "syscalls_extend_2.h"

#define my_syscall3(num, arg1, arg2, arg3)		\
({												\
	my_syscall4(num, arg1, arg2, arg3, NULL);	\
})
#endif //SYSCALLS_EXTEND_HEADER_THREE