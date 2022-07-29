#include "./poll.h"
#include "../syscalls/syscalls.h"

int sys_poll(struct pollfd *fds, int nfds, int timeout)
{
	return my_syscall3(__NR_poll, fds, nfds, timeout);
}
