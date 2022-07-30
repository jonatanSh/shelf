#include "./time.h"
#include "../../syscalls/syscalls.h"

int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	return my_syscall2(__NR_gettimeofday, tv, tz);
}