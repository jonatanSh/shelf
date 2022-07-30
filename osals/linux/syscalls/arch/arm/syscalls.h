#ifndef ARM_SYSCALLS_HEADER
#define ARM_SYSCALLS_HEADER

/* Syscalls for ARM in ARM or Thumb modes :
 *   - registers are 32-bit
 *   - stack is 8-byte aligned
 *     ( http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka4127.html)
 *   - syscall number is passed in r7
 *   - arguments are in r0, r1, r2, r3, r4, r5
 *   - the system call is performed by calling svc #0
 *   - syscall return comes in r0.
 *   - only lr is clobbered.
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 *   - the syscall number is always specified last in order to allow to force
 *     some registers before (gcc refuses a %-register at the last position).
 *
 * Also, ARM supports the old_select syscall if newselect is not available
 */

#include "../generic/syscalls_extend_4.h"

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
({                                                                            \
	register long _num asm("r7") = (num);                                 \
	register long _arg1 asm("r0") = (long)(arg1);                         \
	register long _arg2 asm("r1") = (long)(arg2);                         \
	register long _arg3 asm("r2") = (long)(arg3);                         \
	register long _arg4 asm("r3") = (long)(arg4);                         \
	register long _arg5 asm("r4") = (long)(arg5);                         \
									      \
	asm volatile (                                                        \
		"svc #0\n"                                                    \
		: "=r" (_arg1)                                                \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "r"(_num)                                                   \
		: "memory", "cc", "lr"                                        \
	);                                                                    \
	_arg1;                                                                \
})

#endif // ARM_SYSCALLS_HEADER