#ifndef SELECT_HEADER
#define SELECT_HEADER

#include "../../syscalls/defs.h"

int sys_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout);

#endif /* !SELECT_HEADER */