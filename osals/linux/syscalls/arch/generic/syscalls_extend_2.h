#ifndef SYSCALLS_EXTEND_HEADER_TWO
#define SYSCALLS_EXTEND_HEADER_TWO

#include "syscalls_extend_1.h"

#define my_syscall2(num, arg1, arg2)	\
({										\
	my_syscall3(num, arg1, arg2, NULL);	\
})

#endif //SYSCALLS_EXTEND_HEADER_TWO