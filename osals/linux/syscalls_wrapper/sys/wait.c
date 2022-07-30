#include "./wait.h"
#include "../../syscalls/syscalls.h"

pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	return my_syscall4(__NR_wait4, pid, status, options, rusage);
}

pid_t sys_waitpid(pid_t pid, int *status, int options)
{
	return sys_wait4(pid, status, options, 0);
}

pid_t sys_wait(int *status)
{
	return sys_waitpid(-1, status, 0);
}