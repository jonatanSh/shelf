#include "more.h"
#include "../syscalls/syscalls.h"


int sys_getdents64(int fd, struct linux_dirent64 *dirp, int count)
{
	return my_syscall3(__NR_getdents64, fd, dirp, count);
}

int sys_pivot_root(const char *new, const char *old)
{
	return my_syscall2(__NR_pivot_root, new, old);
}

ssize_t sys_reboot(int magic1, int magic2, int cmd, void *arg)
{
	return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}

int sys_sched_yield(void)
{
	return my_syscall0(__NR_sched_yield);
}