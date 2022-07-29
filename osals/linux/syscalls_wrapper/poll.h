#ifndef POLL_HEADER
#define POLL_HEADER

#include "../linux/syscalls/defs.h"

int sys_poll(struct pollfd *fds, int nfds, int timeout);

#endif /* !POLL_HEADER */