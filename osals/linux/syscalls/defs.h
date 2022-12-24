#ifndef KERNEL_DEFS_HEADER
#define KERNEL_DEFS_HEADER

#define __ARCH_WANT_SYSCALL_NO_AT
#define __ARCH_WANT_SYSCALL_NO_FLAGS
#define __ARCH_WANT_SYSCALL_DEPRECATED
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/loop.h>
#define NOLIBC

/* this way it will be removed if unused */
static int errno;

#ifndef NOLIBC_IGNORE_ERRNO
#define SET_ERRNO(v) do { errno = (v); } while (0)
#else
#define SET_ERRNO(v) do { } while (0)
#endif

/* errno codes all ensure that they will not conflict with a valid pointer
 * because they all correspond to the highest addressable memry page.
 */
#define MAX_ERRNO 4095

/* Declare a few quite common macros and types that usually are in stdlib.h,
 * stdint.h, ctype.h, unistd.h and a few other common locations.
 */

#define NULL ((void *)0)

/* stdint types */
typedef unsigned char       uint8_t;
typedef   signed char        int8_t;
typedef unsigned short     uint16_t;
typedef   signed short      int16_t;
typedef unsigned int       uint32_t;
typedef   signed int        int32_t;
typedef unsigned long long uint64_t;
typedef   signed long long  int64_t;
typedef unsigned long        size_t;
typedef   signed long       ssize_t;
typedef unsigned int      uintptr_t;
typedef   int      		   intptr_t;
typedef   signed long     ptrdiff_t;

/* for stat() */
typedef unsigned int          dev_t;
typedef unsigned long         ino_t;
typedef unsigned int         mode_t;
typedef   signed int          pid_t;
typedef unsigned int          uid_t;
typedef unsigned int          gid_t;
typedef unsigned long       nlink_t;
typedef   signed long         off_t;
typedef   signed long     blksize_t;
typedef   signed long      blkcnt_t;
typedef   signed long        time_t;

/* for poll() */
struct pollfd {
	int fd;
	short int events;
	short int revents;
};

/* for select() */
struct timeval {
	long    tv_sec;
	long    tv_usec;
};

/* for pselect() */
struct timespec {
	long    tv_sec;
	long    tv_nsec;
};

/* for gettimeofday() */
struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

/* for getdents64() */
struct linux_dirent64 {
	uint64_t       d_ino;
	int64_t        d_off;
	unsigned short d_reclen;
	unsigned char  d_type;
	char           d_name[];
};

/* commonly an fd_set represents 256 FDs */
#define FD_SETSIZE 256
typedef struct { uint32_t fd32[FD_SETSIZE/32]; } fd_set;

/* needed by wait4() */
struct rusage {
	struct timeval ru_utime;
	struct timeval ru_stime;
	long   ru_maxrss;
	long   ru_ixrss;
	long   ru_idrss;
	long   ru_isrss;
	long   ru_minflt;
	long   ru_majflt;
	long   ru_nswap;
	long   ru_inblock;
	long   ru_oublock;
	long   ru_msgsnd;
	long   ru_msgrcv;
	long   ru_nsignals;
	long   ru_nvcsw;
	long   ru_nivcsw;
};

/* stat flags (WARNING, octal here) */
#define S_IFDIR       0040000
#define S_IFCHR       0020000
#define S_IFBLK       0060000
#define S_IFREG       0100000
#define S_IFIFO       0010000
#define S_IFLNK       0120000
#define S_IFSOCK      0140000
#define S_IFMT        0170000

#define S_ISDIR(mode)  (((mode) & S_IFDIR) == S_IFDIR)
#define S_ISCHR(mode)  (((mode) & S_IFCHR) == S_IFCHR)
#define S_ISBLK(mode)  (((mode) & S_IFBLK) == S_IFBLK)
#define S_ISREG(mode)  (((mode) & S_IFREG) == S_IFREG)
#define S_ISFIFO(mode) (((mode) & S_IFIFO) == S_IFIFO)
#define S_ISLNK(mode)  (((mode) & S_IFLNK) == S_IFLNK)
#define S_ISSOCK(mode) (((mode) & S_IFSOCK) == S_IFSOCK)

#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK    10
#define DT_SOCK   12

/* all the *at functions */
#ifndef AT_FDWCD
#define AT_FDCWD             -100
#endif

/* lseek */
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2

/* reboot */
#define LINUX_REBOOT_MAGIC1         0xfee1dead
#define LINUX_REBOOT_MAGIC2         0x28121969
#define LINUX_REBOOT_CMD_HALT       0xcdef0123
#define LINUX_REBOOT_CMD_POWER_OFF  0x4321fedc
#define LINUX_REBOOT_CMD_RESTART    0x01234567
#define LINUX_REBOOT_CMD_SW_SUSPEND 0xd000fce2


/* The format of the struct as returned by the libc to the application, which
 * significantly differs from the format returned by the stat() syscall flavours.
 */
struct stat {
	dev_t     st_dev;     /* ID of device containing file */
	ino_t     st_ino;     /* inode number */
	mode_t    st_mode;    /* protection */
	nlink_t   st_nlink;   /* number of hard links */
	uid_t     st_uid;     /* user ID of owner */
	gid_t     st_gid;     /* group ID of owner */
	dev_t     st_rdev;    /* device ID (if special file) */
	off_t     st_size;    /* total size, in bytes */
	blksize_t st_blksize; /* blocksize for file system I/O */
	blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
	time_t    st_atime;   /* time of last access */
	time_t    st_mtime;   /* time of last modification */
	time_t    st_ctime;   /* time of last status change */
};

#define WEXITSTATUS(status)   (((status) & 0xff00) >> 8)
#define WIFEXITED(status)     (((status) & 0x7f) == 0)

#ifndef __NR_getpgrp
	#define __NR_getpgrp sys_getpgrp
#endif

#ifndef __NR_fork
	#define __NR_fork sys_fork
#endif

#ifndef __NR_dup2
	#define __NR_dup2 sys_dup2
#endif


#endif // KERNEL_DEFS_HEADER