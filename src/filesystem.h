/**
 * @internal
 * @file filesystem.h
 * @brief file system mounting functions header
 */
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <sys/stat.h>

// clang-format off
#define JAIL_MNT_RW         0x00000001U
#define JAIL_MNT_SUID       0x00000002U
#define JAIL_MNT_NOEXEC     0x00000004U
#define JAIL_MNT_NOATIME    0x00000008U
#define JAIL_MNT_SYNC       0x00000010U
#define JAIL_MNT_REC        0x00000020U
// clang-format on

struct jail_mount_option {
    char *root, *source, *path, *option;
    unsigned int flags;
};

struct jail_mount_ctx {
    char *type;
    char *source, *target, *fstype;
    unsigned int flags;
    char *data;
};

int get_filetype(const char *path);
int is_same_inode(const char *patha, const char *pathb);
int jail_symlinkat(const char *root, const char *target, int fd, const char *name);
int jail_mount(const char *root, const struct jail_mount_ctx *ctx);

int jail_chroot(const char *path, const char *cdpath);
int privatize_fs();

#endif
