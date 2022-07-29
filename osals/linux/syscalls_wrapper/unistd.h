#ifndef UNISTD_HEADER
#define UNISTD_HEADER

#include "../syscalls/defs.h"

void *sys_brk(void *addr);

void sys_exit(int status);

int sys_chdir(const char *path);

int sys_chown(const char *path, uid_t owner, gid_t group);

int sys_chroot(const char *path);

int sys_close(int fd);

int sys_dup(int fd);

int sys_dup2(int old, int new);

int sys_execve(const char *filename, char *const argv[], char *const envp[]);

pid_t sys_fork(void);

int sys_fsync(int fd);

pid_t sys_getpgrp(void);

pid_t sys_getpid(void);

int sys_link(const char *old, const char *new);

off_t sys_lseek(int fd, off_t offset, int whence);

int sys_open(const char *path, int flags, mode_t mode);

ssize_t sys_read(int fd, void *buf, size_t count);

int sys_setpgid(pid_t pid, pid_t pgid);

pid_t sys_setsid(void);

int sys_symlink(const char *old, const char *new);

int sys_unlink(const char *path);

ssize_t sys_write(int fd, const void *buf, size_t count);

#endif /* !UNISTD_HEADER */