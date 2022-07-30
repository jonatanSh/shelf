#include "./stat.h"
#include "../../syscalls/syscalls.h"

int sys_chmod(const char *path, mode_t mode)
{
#ifdef __NR_fchmodat
	return my_syscall4(__NR_fchmodat, AT_FDCWD, path, mode, 0);
#else
	return my_syscall2(__NR_chmod, path, mode);
#endif
}

int sys_mkdir(const char *path, mode_t mode)
{
#ifdef __NR_mkdirat
	return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#else
	return my_syscall2(__NR_mkdir, path, mode);
#endif
}

long sys_mknod(const char *path, mode_t mode, dev_t dev)
{
#ifdef __NR_mknodat
	return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#else
	return my_syscall3(__NR_mknod, path, mode, dev);
#endif
}

int sys_stat(const char *path, struct stat *buf)
{
	struct sys_stat_struct stat;
	long ret;

#ifdef __NR_newfstatat
	/* only solution for arm64 */
	ret = my_syscall4(__NR_newfstatat, AT_FDCWD, path, &stat, 0);
#else
	ret = my_syscall2(__NR_stat, path, &stat);
#endif
	buf->st_dev     = stat.st_dev;
	buf->st_ino     = stat.st_ino;
	buf->st_mode    = stat.st_mode;
	buf->st_nlink   = stat.st_nlink;
	buf->st_uid     = stat.st_uid;
	buf->st_gid     = stat.st_gid;
	buf->st_rdev    = stat.st_rdev;
	buf->st_size    = stat.st_size;
	buf->st_blksize = stat.st_blksize;
	buf->st_blocks  = stat.st_blocks;
	buf->st_atime   = stat.st_atime;
	buf->st_mtime   = stat.st_mtime;
	buf->st_ctime   = stat.st_ctime;
	return ret;
}

mode_t sys_umask(mode_t mode)
{
	return my_syscall1(__NR_umask, mode);
}
