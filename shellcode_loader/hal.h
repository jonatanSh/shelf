#ifndef SHELLCODE_LOADER_HAL
#define SHELLCODE_LOADER_HAL
#include <ucontext.h>
#include <sys/ucontext.h>
#include <stddef.h>


#if defined(__x86_64__)

#ifdef REG_RIP
    #define UCONTEXT_PC(context) (context.gregs[REG_RIP])
#else
    #define UCONTEXT_PC(context) (*(u_int32_t*)((char*)&context + offsetof(mcontext_t, gregs[14])))
#endif

#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)

#ifdef REG_EIP
    #define UCONTEXT_PC(context) (context.gregs[REG_EIP])
#else
    #define UCONTEXT_PC(context) (*(u_int32_t*)((char*)&context + offsetof(mcontext_t, gregs[14])))
#endif


#elif defined(__ARM_EABI__)

#define UCONTEXT_PC(context) (context.arm_pc)


#elif defined(__aarch64__)

#define UCONTEXT_PC(context) (context.pc)


#elif defined(__mips__) && defined(_ABIO32)

#define UCONTEXT_PC(context) (context.pc)

#elif defined(__riscv) && defined(__riscv_xlen) && (__riscv_xlen == 64)

#define UCONTEXT_PC(context) ((size_t)(((struct sigcontext*)&context)->gregs[REG_RA]))

#endif

#endif