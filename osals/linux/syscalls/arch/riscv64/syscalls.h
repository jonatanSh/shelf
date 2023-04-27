#ifndef RISCV64_SYSCALLS_HEADER
#define RISCV64_SYSCALLS_HEADER
/* Syscalls for RISCV64 :
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

#define my_syscall6(id, a1, a2, a3, a4, a5, a6) \
  ({ \
    register unsigned long a7 asm("a7") = (unsigned long)(id); \
    register unsigned long __a0 asm("a0") = (unsigned long)(a1); \
    register unsigned long __a1 asm("a1") = (unsigned long)(a2); \
    register unsigned long __a2 asm("a2") = (unsigned long)(a3); \
    register unsigned long __a3 asm("a3") = (unsigned long)(a4); \
    register unsigned long __a4 asm("a4") = (unsigned long)(a5); \
    register unsigned long __a5 asm("a5") = (unsigned long)(a6); \
    asm volatile ("ecall" \
                  : "+r"(a7), "=r"(__a0), "=r"(__a1), "=r"(__a2), "=r"(__a3), "=r"(__a4), "=r"(__a5) \
                  : \
                  : "memory"); \
    __a0; \
  })

#endif // RISCV64_SYSCALLS_HEADER