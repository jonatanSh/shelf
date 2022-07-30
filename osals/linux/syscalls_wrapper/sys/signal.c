#include "./signal.h"
#include "../../syscalls/syscalls.h"

int sys_kill(pid_t pid, int signal)
{
	return my_syscall2(__NR_kill, pid, signal);
}