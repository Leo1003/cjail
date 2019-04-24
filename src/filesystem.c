/**
 * @internal
 * @file filesystem.c
 * @brief file system mounting functions source
 */
#define _GNU_SOURCE
#include "filesystem.h"
#include "logger.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

int get_filetype(const char *path)
{
    struct stat st;
    if (stat(path, &st)) {
        return -1;
    }
    return (st.st_mode & S_IFMT);
}

int get_fstype(const char *path)
{
    struct statfs stf;
    if (statfs(path, &stf)) {
        return -1;
    }
    return stf.f_type;
}

int get_fdpath(int fd, char *path, size_t len)
{
    char fdpath[PATH_MAX];
    pathprintf(fdpath, "/proc/self/fd/%d", fd);
    int ret = readlink(fdpath, path, len);
    if (ret < 0 && errno == ENOENT) {
        errno = EBADF;
    }
    return ret;
}

int is_same_inode(const char *patha, const char *pathb)
{
    if (!patha || !pathb) {
        errno = EINVAL;
        return 0;
    }
    struct stat sta, stb;
    if (stat(patha, &sta) || stat(pathb, &stb)) {
        return 0;
    }
    devf("%s <=> %s\n", patha, pathb);
    devf("%lu:%lu <=> %lu:%lu\n", sta.st_dev, sta.st_ino, stb.st_dev, stb.st_ino);
    return (sta.st_dev == stb.st_dev) && (sta.st_ino == stb.st_ino);
}

int jail_symlinkat(const char *root, const char *target, int fd, const char *name)
{
    char path[PATH_MAX];
    combine_path(path, root, target);
    return symlinkat(path, fd, name);
}

int try_umount(const char *path)
{
    if (umount2(path, UMOUNT_NOFOLLOW) == 0) {
        return 0;
    }
    if (errno != EBUSY) {
        return -1;
    }
    return umount2(path, MNT_DETACH | UMOUNT_NOFOLLOW);
}

int jail_mount(const char *root, const struct jail_mount_ctx *ctx)
{
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }
    const struct mnt_ops *ops = mnt_ops_find(ctx->type);
    if (!ops || !ops->fn) {
        errno = EINVAL;
        return -1;
    }

    char path[PATH_MAX];
    if (root) {
        combine_path(path, root, ctx->target);
    } else {
        strncpy(path, ctx->target, sizeof(path));
    }

    struct jail_mount_ctx cctx;
    memcpy(&cctx, ctx, sizeof(struct jail_mount_ctx));
    cctx.target = path;

    /* Apply flags mask here */
    cctx.flags &= ops->mask;
    debugf("Mounting type %s on %s [%#x]\n", cctx.type, cctx.target, cctx.flags);
    return ops->fn(&cctx);
}

int jail_chroot(const char *path, const char *cdpath)
{
    if (path) {
        if (chroot(path) || chdir("/")) {
            PERR("chroot");
            return -1;
        }
    }
    if (cdpath) {
        if (chdir(cdpath)) {
            PERR("chdir");
            return -1;
        }
    }
    return 0;
}

int privatize_fs()
{
    if (mount("", "/", "", MS_REC | MS_PRIVATE, NULL)) {
        PFTL("privatize filesystem");
        return -1;
    }
    return 0;
}

struct jail_mount_list *mnt_list_new()
{
    struct jail_mount_list *ml = (struct jail_mount_list *)malloc(sizeof(struct jail_mount_list));
    if (!ml) {
        return NULL;
    }
    memset(ml, 0, sizeof(struct jail_mount_list));
    return ml;
}

void mnt_list_free(struct jail_mount_list *ml)
{
    if (!ml) {
        return;
    }

    mnt_list_clear(ml);
    free(ml);
}

int mnt_list_add(struct jail_mount_list *ml, const struct jail_mount_ctx *ctx)
{
    if (!ml) {
        errno = EINVAL;
        return -1;
    }

    struct jail_mount_node *node = mount_node_new();
    if (!node) {
        return -1;
    }

    mount_node_set_ctx(node, ctx);
    node->next = NULL;
    if (!ml->end) {
        ml->head = ml->end = node;
    } else {
        ml->end->next = node;
        ml->end = node;
    }
    return 0;
}

int mnt_list_clear(struct jail_mount_list *ml)
{
    if (!ml) {
        errno = EINVAL;
        return -1;
    }

    struct jail_mount_node *cur = ml->head, *next = NULL;
    while (cur) {
        next = cur->next;
        mount_node_free(cur);
        cur = next;
    }
    ml->head = ml->end = NULL;
    return 0;
}

static struct mnt_ops *mnt_ops_head = NULL;

static struct mnt_ops *mnt_ops_find_prev(const char *name, struct mnt_ops **ops, struct mnt_ops **prev)
{
    struct mnt_ops *ops_cur = mnt_ops_head, *ops_prev = NULL;
    if (!name) {
        errno = EINVAL;
        return NULL;
    }
    while (ops_cur) {
        if (!strncmp(name, ops_cur->name, MNT_OPS_NAME_LEN)) {
            break;
        }
        ops_prev = ops_cur;
        ops_cur = ops_cur->next;
    }
    if (ops) {
        *ops = ops_cur;
    }
    if (prev) {
        *prev = ops_prev;
    }
    return ops_cur;
}

int mnt_ops_register(const struct mnt_ops *ops)
{
    if (!ops || !ops->fn) {
        errno = EINVAL;
        return -1;
    }
    /* Check not duplicate and get the last item */
    struct mnt_ops *ops_cur = mnt_ops_head, *ops_prev = mnt_ops_head;
    mnt_ops_find_prev(ops->name, &ops_cur, &ops_prev);
    if (ops_cur) {
        errno = EEXIST;
        return -1;
    }
    /* Copy and link to the list */
    struct mnt_ops *cops = (struct mnt_ops *)malloc(sizeof(struct mnt_ops));
    if (!cops) {
        return -1;
    }
    memcpy(cops, ops, sizeof(struct mnt_ops));
    cops->next = NULL;

    if (!ops_prev) {
        mnt_ops_head = cops;
    } else {
        ops_prev->next = cops;
    }
    return 0;
}

int mnt_ops_deregister(const char *name)
{
    if (!name) {
        errno = EINVAL;
        return -1;
    }
    struct mnt_ops *ops_cur = mnt_ops_head, *ops_prev = mnt_ops_head;
    mnt_ops_find_prev(name, &ops_cur, &ops_prev);
    if (!ops_cur) {
        errno = ENOENT;
        return -1;
    }
    /* Unlink and free */
    if (!ops_prev) {
        mnt_ops_head = ops_cur->next;
    } else {
        ops_prev->next = ops_cur->next;
    }
    free(ops_cur);
    return 0;
}

const struct mnt_ops *mnt_ops_find(const char *name)
{
    return mnt_ops_find_prev(name, NULL, NULL);
}

struct jail_mount_node *mount_node_new()
{
    struct jail_mount_node *node = (struct jail_mount_node *)malloc(sizeof(struct jail_mount_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct jail_mount_node));
    return node;
}

static char *node_set_string(char **orig_s, const char *new_s, size_t size)
{
    if (new_s) {
        if (!*orig_s) {
            *orig_s = (char *)malloc(sizeof(char) * (size));
            if (!*orig_s) {
                /* Allocation failed */
                *orig_s = NULL;
                return *orig_s;
            }
        }
        strncpy(*orig_s, new_s, sizeof(char) * (size));
        *orig_s[size - 1] = '\0';   /* Prevent strncpy() not writing null character */
    } else {
        if (*orig_s) {
            /* Free memory and set to NULL */
            free(*orig_s);
            *orig_s = NULL;
        }
    }
    return *orig_s;
}

void mount_node_set_ctx(struct jail_mount_node *node, const struct jail_mount_ctx *ctx)
{
    if (!node) {
        return;
    }

    node_set_string(&node->ctx.type, ctx->type, MNT_OPS_NAME_LEN);
    node_set_string(&node->ctx.source, ctx->source, PATH_MAX);
    node_set_string(&node->ctx.target, ctx->target, PATH_MAX);
    node_set_string(&node->ctx.fstype, ctx->fstype, PATH_MAX);
    node_set_string(&node->ctx.data, ctx->data, 4096);
    node->ctx.flags = ctx->flags;
}

void mount_node_free(struct jail_mount_node *node)
{
    if (!node) {
        return;
    }

    free(node->ctx.type);
    free(node->ctx.source);
    free(node->ctx.target);
    free(node->ctx.fstype);
    free(node->ctx.data);

    free(node);
}

static void mnt_ops_fini() __attribute__((destructor));
static void mnt_ops_fini()
{
    struct mnt_ops *ops_cur = mnt_ops_head, *ops_prev = NULL;
    while (ops_cur) {
        ops_prev = ops_cur;
        ops_cur = ops_cur->next;
        free(ops_prev);
    }
    mnt_ops_head = NULL;
}
