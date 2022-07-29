#ifndef MMAN_HEADER
#define MMAN_HEADER

#include "../../syscalls/defs.h"
#include <linux/mman.h>

#define SYS_legacy_mmap 0x5a
#define UNIT 8192ULL
#define OFF_MASK ((-0x2000ULL << (8*sizeof(long)-1)) | (UNIT-1))

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};


void *sys_mmap(void *start, size_t len, int prot, int flags, int fd, off_t off);

int sys_mprotect(void *addr, size_t start, size_t len, int prot);

int sys_munmap(void *start, size_t len);

#endif /* !MMAN_HEADER */