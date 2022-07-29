#ifndef X86_64_SYSCALLS_HEADER
#define X86_64_SYSCALLS_HEADER
/* Syscalls for x86_64 :
 *   - registers are 64-bit
 *   - syscall number is passed in rax
 *   - arguments are in rdi, rsi, rdx, r10, r8, r9 respectively
 *   - the system call is performed by calling the syscall instruction
 *   - syscall return comes in rax
 *   - rcx and r8..r11 may be clobbered, others are preserved.
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 *   - the syscall number is always specified last in order to allow to force
 *     some registers before (gcc refuses a %-register at the last position).
 */

#include "../generic/syscalls_extend_5.h"

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
	long _ret;                                                            \
	register long _num  asm("rax") = (num);                               \
	register long _arg1 asm("rdi") = (long)(arg1);                        \
	register long _arg2 asm("rsi") = (long)(arg2);                        \
	register long _arg3 asm("rdx") = (long)(arg3);                        \
	register long _arg4 asm("r10") = (long)(arg4);                        \
	register long _arg5 asm("r8")  = (long)(arg5);                        \
	register long _arg6 asm("r9")  = (long)(arg6);                        \
									      \
	asm volatile (                                                        \
		"syscall\n"                                                   \
		: "=a" (_ret), "=r"(_arg4), "=r"(_arg5)                       \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "r"(_arg6), "0"(_num)                                       \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#endif // X86_64_SYSCALLS_HEADER