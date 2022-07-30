#ifndef ARM_64_DEFS_HEADER
#define ARM_64_DEFS_HEADER


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

/* The struct returned by the newfstatat() syscall. Differs slightly from the
 * x86_64's stat one by field ordering, so be careful.
 */
struct sys_stat_struct {
	unsigned long   st_dev;
	unsigned long   st_ino;
	unsigned int    st_mode;
	unsigned int    st_nlink;
	unsigned int    st_uid;
	unsigned int    st_gid;

	unsigned long   st_rdev;
	unsigned long   __pad1;
	long            st_size;
	int             st_blksize;
	int             __pad2;

	long            st_blocks;
	long            st_atime;
	unsigned long   st_atime_nsec;
	long            st_mtime;

	unsigned long   st_mtime_nsec;
	long            st_ctime;
	unsigned long   st_ctime_nsec;
	unsigned int    __unused[2];
};
#endif // ARM_64_DEFS_HEADER