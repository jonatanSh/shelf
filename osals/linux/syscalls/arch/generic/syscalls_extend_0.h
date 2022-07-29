#ifndef SYSCALLS_EXTEND_HEADER_ZERO
#define SYSCALLS_EXTEND_HEADER_ZERO

#define my_syscall0(num)	\
({							\
	my_syscall1(num, NULL);	\
})

#endif //SYSCALLS_EXTEND_HEADER_ZERO