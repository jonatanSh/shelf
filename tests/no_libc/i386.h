#ifndef I386_SYSCALLS
#define I386_SYSCALLS
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
#endif