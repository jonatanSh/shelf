#ifndef IOCTL_HEADER
#define IOCTL_HEADER

#include "../../syscalls/defs.h"

int sys_ioctl(int fd, unsigned long req, void *value);

#endif /* !IOCTL_HEADER */