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

int jail_mount(char *source, char *root, char *target, unsigned flags, char *option);
int jail_chroot(char *path, char *cdpath);
int privatize_fs();

#endif
