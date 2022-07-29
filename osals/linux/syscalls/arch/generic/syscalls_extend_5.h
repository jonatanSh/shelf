#ifndef SYSCALLS_EXTEND_HEADER_FIVE
#define SYSCALLS_EXTEND_HEADER_FIVE

#include "syscalls_extend_4.h"

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)    	\
({															\
	my_syscall6(num, arg1, arg2, arg3, arg4, arg5, NULL);	\
})
#endif //SYSCALLS_EXTEND_HEADER_FIVE