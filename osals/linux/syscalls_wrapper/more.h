#ifndef MORE_HEADER
#define MORE_HEADER

/*
	here i implemented syscalls that are not implemented in libc 
*/

#include "../linux/syscalls/defs.h"

int sys_getdents64(int fd, struct linux_dirent64 *dirp, int count);

int sys_pivot_root(const char *new, const char *old);


ssize_t sys_reboot(int magic1, int magic2, int cmd, void *arg);

int sys_sched_yield(void);

#endif /* !MORE_HEADER */