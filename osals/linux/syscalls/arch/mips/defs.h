#ifndef MIPS_DEFS_HEADER
#define MIPS_DEFS_HEADER

/* fcntl / open */
#define O_RDONLY            0
#define O_WRONLY            1
#define O_RDWR              2
#define O_APPEND       0x0008
#define O_NONBLOCK     0x0080
#define O_CREAT        0x0100
#define O_TRUNC        0x0200
#define O_EXCL         0x0400
#define O_NOCTTY       0x0800
#define O_DIRECTORY   0x10000

/* The struct returned by the stat() syscall. 88 bytes are returned by the
 * syscall.
 */
struct sys_stat_struct {
	unsigned int  st_dev;
	long          st_pad1[3];
	unsigned long st_ino;
	unsigned int  st_mode;
	unsigned int  st_nlink;
	unsigned int  st_uid;
	unsigned int  st_gid;
	unsigned int  st_rdev;
	long          st_pad2[2];
	long          st_size;
	long          st_pad3;
	long          st_atime;
	long          st_atime_nsec;
	long          st_mtime;
	long          st_mtime_nsec;
	long          st_ctime;
	long          st_ctime_nsec;
	long          st_blksize;
	long          st_blocks;
	long          st_pad4[14];
};

#endif // MIPS_DEFS_HEADER