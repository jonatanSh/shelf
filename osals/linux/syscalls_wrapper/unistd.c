#include "./unistd.h"
#include "../syscalls/syscalls.h"

void *sys_brk(void *addr)
{
	return (void *)my_syscall1(__NR_brk, addr);
}

void sys_exit(int status)
{
	my_syscall1(__NR_exit, status & 255);
	while(1); // shut the "noreturn" warnings.
}

int sys_chdir(const char *path)
{
	return my_syscall1(__NR_chdir, path);
}


int sys_chown(const char *path, uid_t owner, gid_t group)
{
#ifdef __NR_fchownat
	return my_syscall5(__NR_fchownat, AT_FDCWD, path, owner, group, 0);
#else
	return my_syscall3(__NR_chown, path, owner, group);
#endif
}

int sys_chroot(const char *path)
{
	return my_syscall1(__NR_chroot, path);
}

int sys_close(int fd)
{
	return my_syscall1(__NR_close, fd);
}

int sys_dup(int fd)
{
	return my_syscall1(__NR_dup, fd);
}

int sys_dup2(int old, int new)
{
	return my_syscall2(__NR_dup2, old, new);
}

int sys_execve(const char *filename, char *const argv[], char *const envp[])
{
	return my_syscall3(__NR_execve, filename, argv, envp);
}

pid_t sys_fork(void)
{
	return my_syscall0(__NR_fork);
}

int sys_fsync(int fd)
{
	return my_syscall1(__NR_fsync, fd);
}

pid_t sys_getpgrp(void)
{
	return my_syscall0(__NR_getpgrp);
}

pid_t sys_getpid(void)
{
	return my_syscall0(__NR_getpid);
}

int sys_link(const char *old, const char *new)
{
#ifdef __NR_linkat
	return my_syscall5(__NR_linkat, AT_FDCWD, old, AT_FDCWD, new, 0);
#else
	return my_syscall2(__NR_link, old, new);
#endif
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
	return my_syscall3(__NR_lseek, fd, offset, whence);
}

int sys_open(const char *path, int flags, mode_t mode)
{
#ifdef __NR_openat
	return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#else
	return my_syscall3(__NR_open, path, flags, mode);
#endif
}

ssize_t sys_read(int fd, void *buf, size_t count)
{
	return my_syscall3(__NR_read, fd, buf, count);
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
	return my_syscall2(__NR_setpgid, pid, pgid);
}

pid_t sys_setsid(void)
{
	return my_syscall0(__NR_setsid);
}

int sys_symlink(const char *old, const char *new)
{
#ifdef __NR_symlinkat
	return my_syscall3(__NR_symlinkat, old, AT_FDCWD, new);
#else
	return my_syscall2(__NR_symlink, old, new);
#endif
}


int sys_unlink(const char *path)
{
#ifdef __NR_unlinkat
	return my_syscall3(__NR_unlinkat, AT_FDCWD, path, 0);
#else
	return my_syscall1(__NR_unlink, path);
#endif
}

ssize_t write(int fd, const void *buf, size_t count)
{
	return my_syscall3(__NR_write, fd, buf, count);
}
