#ifndef ARM_64_SYSCALLS_HEADER
#define ARM_64_SYSCALLS_HEADER

/* Syscalls for AARCH64 :
 *   - registers are 64-bit
 *   - stack is 16-byte aligned
 *   - syscall number is passed in x8
 *   - arguments are in x0, x1, x2, x3, x4, x5
 *   - the system call is performed by calling svc 0
 *   - syscall return comes in x0.
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 *
 * On aarch64, select() is not implemented so we have to use pselect6().
 */
#define __ARCH_WANT_SYS_PSELECT6

#include "../generic/syscalls_extend_5.h"

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
	register long _num  asm("x8") = (long)(num);                                \
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

#endif // ARM_64_SYSCALLS_HEADER