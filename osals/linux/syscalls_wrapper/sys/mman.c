#include "./mman.h"
#include "../../syscalls/syscalls.h"

void * sys_mmap(void *start, size_t len, int prot, int flags, int fd, off_t offset)
{
	long ret;
#ifdef my_syscall6
#ifdef __NR_mmap2
	ret = my_syscall6(__NR_mmap2, start, len, prot, flags, fd, offset/UNIT);
#else
	ret = my_syscall6(__NR_mmap, start, len, prot, flags, fd, offset);
#endif

#else // we will use legacy mmap
	struct mmap_arg_struct args;
	args.addr = (long)start;
	args.len = len;
	args.prot = prot;
	args.flags = flags;
	args.fd = fd;
	args.offset = offset;
	ret = my_syscall1(SYS_legacy_mmap, &args);
#endif
	return (void *)ret;
}

int sys_mprotect(void *addr, size_t start, size_t len, int prot)
{
	return my_syscall3(__NR_mprotect, start, len, prot);
}

int sys_munmap(void *start, size_t len)
{
	return my_syscall2(__NR_munmap, start, len);
}
