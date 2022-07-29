#ifndef WAIT_HEADER
#define WAIT_HEADER

#include "../../syscalls/defs.h"

pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage);

pid_t sys_waitpid(pid_t pid, int *status, int options);

pid_t sys_wait(int *status);

#endif /* !WAIT_HEADER */