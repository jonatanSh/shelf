#include "./ioctl.h"
#include "../../syscalls/syscalls.h"

int sys_ioctl(int fd, unsigned long req, void *value)
{
	return my_syscall3(__NR_ioctl, fd, req, value);
}