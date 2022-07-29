#ifndef SYSCALLS_EXTEND_HEADER_ONE
#define SYSCALLS_EXTEND_HEADER_ONE

#include "syscalls_extend_0.h"

#define my_syscall1(num, arg1)		\
({									\
	my_syscall2(num, arg1, NULL);	\
})

#endif //SYSCALLS_EXTEND_HEADER_ONE