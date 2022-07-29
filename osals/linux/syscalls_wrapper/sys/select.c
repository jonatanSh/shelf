#include "./select.h"
#include "../../syscalls/syscalls.h"

int sys_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
#if defined(__ARCH_WANT_SYS_OLD_SELECT) && !defined(__NR__newselect)
	struct sel_arg_struct {
		unsigned long n;
		fd_set *r, *w, *e;
		struct timeval *t;
	} arg = { .n = nfds, .r = rfds, .w = wfds, .e = efds, .t = timeout };
	return my_syscall1(__NR_select, &arg);
#elif defined(__ARCH_WANT_SYS_PSELECT6) && defined(__NR_pselect6)
	struct timespec t;

	if (timeout) {
		t.tv_sec  = timeout->tv_sec;
		t.tv_nsec = timeout->tv_usec * 1000;
	}
	return my_syscall6(__NR_pselect6, nfds, rfds, wfds, efds, timeout ? &t : NULL, NULL);
#else
#ifndef __NR__newselect
#define __NR__newselect __NR_select
#endif
	return my_syscall5(__NR__newselect, nfds, rfds, wfds, efds, timeout);
#endif
}