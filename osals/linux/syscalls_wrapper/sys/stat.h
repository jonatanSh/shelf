#ifndef STAT_HEADER
#define STAT_HEADER

#include "../../syscalls/defs.h"

int sys_chmod(const char *path, mode_t mode);

int sys_mkdir(const char *path, mode_t mode);

long sys_mknod(const char *path, mode_t mode, dev_t dev);

int sys_stat(const char *path, struct stat *buf);

mode_t sys_umask(mode_t mode);

#endif /* !STAT_HEADER */