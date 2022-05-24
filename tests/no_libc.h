#ifndef NO_LIBC
#define NO_LIBC
#include <sys/syscall.h>
#if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #include "./no_libc/i386.h"
#elif defined(__aarch64__)
    #include "./no_libc/aarch64.h"
#endif

#define print_out(message, size) {\
    my_syscall5(SYS_write, 1, message, size, 0, 0);\
}\

#endif