#include "./mount.h"
#include "../../syscalls/syscalls.h"

int sys_mount(const char *src, const char *tgt, const char *fst,
	      unsigned long flags, const void *data)
{
	return my_syscall5(__NR_mount, src, tgt, fst, flags, data);
}

int sys_umount2(const char *path, int flags)
{
	return my_syscall2(__NR_umount2, path, flags);
}