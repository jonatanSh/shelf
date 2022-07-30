#ifndef TIME_HEADER
#define TIME_HEADER

#include "../../syscalls/defs.h"

int sys_gettimeofday(struct timeval *tv, struct timezone *tz);

#endif /* !TIME_HEADER */