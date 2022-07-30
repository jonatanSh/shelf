#ifndef MOUNT_HEADER
#define MOUNT_HEADER

#include "../../syscalls/defs.h"

int sys_mount(const char *src, const char *tgt, const char *fst,
	      unsigned long flags, const void *data);


int sys_umount2(const char *path, int flags);


#endif /* !MOUNT_HEADER */