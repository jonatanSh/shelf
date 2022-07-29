#ifndef I386_SYSCALL_HEADER
#define I386_SYSCALL_HEADER
/* Syscalls for i386 :
 *   - mostly similar to x86_64
 *   - registers are 32-bit
 *   - syscall number is passed in eax
 *   - arguments are in ebx, ecx, edx, esi, edi, ebp respectively
 *   - all registers are preserved (except eax of course)
 *   - the system call is performed by calling int $0x80
 *   - syscall return comes in eax
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 *   - the syscall number is always specified last in order to allow to force
 *     some registers before (gcc refuses a %-register at the last position).
 *
 * Also, i386 supports the old_select syscall if newselect is not available
 */
#define __ARCH_WANT_SYS_OLD_SELECT

#include "../generic/syscalls_extend_4.h"

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
({                                                                            \
	long _ret;                                                            \
	register long _num asm("eax") = (num);                                \
	register long _arg1 asm("ebx") = (long)(arg1);                        \
	register long _arg2 asm("ecx") = (long)(arg2);                        \
	register long _arg3 asm("edx") = (long)(arg3);                        \
	register long _arg4 asm("esi") = (long)(arg4);                        \
	register long _arg5 asm("edi") = (long)(arg5);                        \
									      \
	asm volatile (                                                        \
		"int $0x80\n"                                                 \
		: "=a" (_ret)                                                 \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "0"(_num)                                                   \
		: "memory", "cc"                                              \
	);                                                                    \
	_ret;                                                                 \
})


#endif // I386_SYSCALL_HEADER