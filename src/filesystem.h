/**
 * @internal
 * @file filesystem.h
 * @brief file system mounting functions header
 */
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <cjail/filesystem.h>

#include <stddef.h>
#include <sys/stat.h>

int get_filetype(const char *path);
int get_fstype(const char *path);
int get_fdpath(int fd, char *path, size_t len);
int is_same_inode(const char *patha, const char *pathb);

int jail_symlinkat(const char *root, const char *target, int fd, const char *name);
int jail_mount(const char *root, const struct jail_mount_ctx *ctx);
int try_umount(const char *path);
int jail_chroot(const char *path, const char *cdpath);
int privatize_fs();

struct jail_mount_node *mount_node_new();
void mount_node_set_ctx(struct jail_mount_node *node, const struct jail_mount_ctx *ctx);
void mount_node_free(struct jail_mount_node *node);

struct jail_mount_node {
    struct jail_mount_ctx ctx;
    struct jail_mount_node *next;
};
struct jail_mount_list {
    struct jail_mount_node *head, *end;
};

#endif
