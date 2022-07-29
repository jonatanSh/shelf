#ifndef ARM_DEFS_HEADER
#define ARM_DEFS_HEADER

/* fcntl / open */
#define O_RDONLY            0
#define O_WRONLY            1
#define O_RDWR              2
#define O_CREAT          0x40
#define O_EXCL           0x80
#define O_NOCTTY        0x100
#define O_TRUNC         0x200
#define O_APPEND        0x400
#define O_NONBLOCK      0x800
#define O_DIRECTORY    0x4000

/* The struct returned by the stat() syscall, 32-bit only, the syscall returns
 * exactly 56 bytes (stops before the unused array). In big endian, the format
 * differs as devices are returned as short only.
 */
struct sys_stat_struct {
#if defined(__ARMEB__)
	unsigned short st_dev;
	unsigned short __pad1;
#else
	unsigned long  st_dev;
#endif
	unsigned long  st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
#if defined(__ARMEB__)
	unsigned short st_rdev;
	unsigned short __pad2;
#else
	unsigned long  st_rdev;
#endif
	unsigned long  st_size;
	unsigned long  st_blksize;
	unsigned long  st_blocks;
	unsigned long  st_atime;
	unsigned long  st_atime_nsec;
	unsigned long  st_mtime;
	unsigned long  st_mtime_nsec;
	unsigned long  st_ctime;
	unsigned long  st_ctime_nsec;
	unsigned long  __unused[2];
};

#endif // ARM_DEFS_HEADER