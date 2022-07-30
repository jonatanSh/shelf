#ifndef SIGNAL_HEADER
#define SIGNAL_HEADER

#include "../../syscalls/defs.h"

int sys_kill(pid_t pid, int signal);

#endif /* !SIGNAL_HEADER */