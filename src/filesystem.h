#ifndef FILESYSTEM_H
#define FILESYSTEM_H

enum fs_type {
    FS_DISK,
    FS_BIND,
    FS_TMP,
    FS_PROC,
    FS_DEV,
    FS_SYS,
    FS_UDEV,
    FS_RW = 16,
    FS_NOEXEC = 32,
    FS_SUID = 64
};

struct jail_mount_option {
    char *root, *source, *path, *option;
    unsigned int flags;
};

int get_filetype(const char *path);
int is_same_inode(const char *patha, const char *pathb);
int jail_symlinkat(const char *root, const char *target, int fd, const char *name);
int jail_mount(const char *source, const char *root, const char *target,
               unsigned flags, const char *option);
int jail_chroot(const char *path, const char *cdpath);
int privatize_fs();

#endif
