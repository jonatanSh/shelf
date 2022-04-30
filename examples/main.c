#include <sys/syscall.h>

#define syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
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

unsigned int write(int fd, char * buffer, unsigned int sz) {
    syscall5(SYS_write,fd, buffer, sz, 0, 0);
}


unsigned int strlen(const char *str)
{
    unsigned int length = 0;

    while (*str++)
        length++;

    return (length);
}

void main() {
    char * message = "Hello from shellcode !\n";
    write(1, message, strlen(message));
}