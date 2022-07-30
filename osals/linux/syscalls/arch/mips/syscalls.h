#ifndef MIPS_SYSCALLS_HEADER
#define MIPS_SYSCALLS_HEADER
/* Syscalls for MIPS ABI O32 :
 *   - WARNING! there's always a delayed slot!
 *   - WARNING again, the syntax is different, registers take a '$' and numbers
 *     do not.
 *   - registers are 32-bit
 *   - stack is 8-byte aligned
 *   - syscall number is passed in v0 (starts at 0xfa0).
 *   - arguments are in a0, a1, a2, a3, then the stack. The caller needs to
 *     leave some room in the stack for the callee to save a0..a3 if needed.
 *   - Many registers are clobbered, in fact only a0..a2 and s0..s8 are
 *     preserved. See: https://www.linux-mips.org/wiki/Syscall as well as
 *     scall32-o32.S in the kernel sources.
 *   - the system call is performed by calling "syscall"
 *   - syscall return comes in v0, and register a3 needs to be checked to know
 *     if an error occured, in which case errno is in v0.
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 */

#include "../generic/syscalls_extend_4.h"

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
({                                                                            \
	register long _num asm("v0") = (num);                                 \
	register long _arg1 asm("a0") = (long)(arg1);                         \
	register long _arg2 asm("a1") = (long)(arg2);                         \
	register long _arg3 asm("a2") = (long)(arg3);                         \
	register long _arg4 asm("a3") = (long)(arg4);                         \
	register long _arg5 = (long)(arg5);				      \
									      \
	asm volatile (                                                        \
		"addiu $sp, $sp, -32\n"                                       \
		"sw %7, 16($sp)\n"                                            \
		"syscall\n  "                                                 \
		"addiu $sp, $sp, 32\n"                                        \
		: "=r" (_num), "=r"(_arg4)                                    \
		: "0"(_num),                                                  \
		  "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5)  \
		: "memory", "cc", "at", "v1", "hi", "lo",                     \
		  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"  \
	);                                                                    \
	_arg4 ? -_num : _num;                                                 \
})

#endif // MIPS_SYSCALLS_HEADER