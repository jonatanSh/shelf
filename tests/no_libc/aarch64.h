#ifndef AARCH64_SYSCALLS
#define AARCH64_SYSCALLS

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
	register long _num  asm("x8") = (num);                                \
	register long _arg1 asm("x0") = (long)(arg1);                         \
	register long _arg2 asm("x1") = (long)(arg2);                         \
	register long _arg3 asm("x2") = (long)(arg3);                         \
	register long _arg4 asm("x3") = (long)(arg4);                         \
	register long _arg5 asm("x4") = (long)(arg5);                         \
	register long _arg6 asm("x5") = (long)(arg6);                         \
									      \
	asm volatile (                                                        \
		"svc #0\n"                                                    \
		: "=r" (_arg1)                                                \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "r"(_arg6), "r"(_num)                                       \
		: "memory", "cc"                                              \
	);                                                                    \
	_arg1;                                                                \
})

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5) my_syscall6(num, arg1, arg2, arg3, arg4, arg5, 0);
#endif