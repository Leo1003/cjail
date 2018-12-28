/**
 * @internal
 * @file filesystem.c
 * @brief file system mounting functions source
 */
#define _GNU_SOURCE
#include "filesystem.h"
#include "logger.h"
#include "loop.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC 0x01021994
#endif

/* clang-format off */
#define NBIND_MASKOUT   (~(JAIL_MNT_REC))
#define SYSFS_MASKOUT   (~(JAIL_MNT_NOEXEC | JAIL_MNT_SUID | JAIL_MNT_SYNC | JAIL_MNT_REC))
/* clang-format on  */

typedef int (*mount_oper_fn)(const struct jail_mount_ctx *);
struct mount_operator {
    char *name;
    mount_oper_fn fn;
};

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

inline static int try_umount(const char *path)
{
    if (umount2(path, UMOUNT_NOFOLLOW) == 0) {
        return 0;
    }
    if (errno != EBUSY) {
        return -1;
    }
    return umount2(path, MNT_DETACH | UMOUNT_NOFOLLOW);
}

static int mount_loop(const struct jail_mount_ctx *ctx)
{
    int loopfd, loopflags = LOOP_AUTO_DETACH;

    if (!(ctx->flags & JAIL_MNT_RW)) loopflags |= LOOP_LOAD_READONLY;

    if ((loopfd = loop_load(ctx->source, loopflags, NULL)) < 0) {
        PERR("mount loop");
        return -1;
    }

    char looppath[PATH_MAX];
    if (get_fdpath(loopfd, looppath, sizeof(looppath)) < 0) {
        close(loopfd);
        return -1;
    }
    debugf("Loaded loop file: %s -> %s\n", ctx->source, looppath);

    struct jail_mount_ctx mctx = {
        .type = "block",
        .source = looppath,
        .target = ctx->target,
        .fstype = ctx->fstype,
        .flags = ctx->flags,
        .data = ctx->data
    };
    /* The target has already chrooted, so the root argument can just pass NULL */
    if (jail_mount(NULL, &mctx) < 0) {
        close(loopfd);
        return -1;
    }
    close(loopfd);
    return 0;
}


static unsigned int convert_flags(unsigned int flags, unsigned int mask, unsigned int setflags)
{
    unsigned int maskflags = flags & mask;

    if (!(maskflags & JAIL_MNT_RW)) setflags |= MS_RDONLY;
    if (maskflags & JAIL_MNT_NOEXEC) setflags |= MS_NOEXEC;
    if (!(maskflags & JAIL_MNT_SUID)) setflags |= MS_NOSUID;
    if (maskflags & JAIL_MNT_SYNC) setflags |= (MS_SYNCHRONOUS | MS_DIRSYNC);
    if (maskflags & JAIL_MNT_NOATIME) setflags |= MS_NOATIME;
    if (maskflags & JAIL_MNT_REC) setflags |= MS_REC;

    return setflags;
}

static int mount_disk(const struct jail_mount_ctx *ctx)
{
    if (get_filetype(ctx->source) != S_IFBLK) {
        errno = EINVAL;
        return -1;
    }

    unsigned int mountflags = convert_flags(ctx->flags, NBIND_MASKOUT, MS_NODEV);

    if (mount(ctx->source, ctx->target, ctx->fstype, mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_bind(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags, 0, MS_BIND | MS_NODEV);

    if (mount(ctx->source, ctx->target, NULL, MS_BIND, NULL)) {
        return -1;
    }
    /* Apply other flags using remount */
    mountflags |= MS_REMOUNT;

    if (mount(NULL, ctx->target, NULL, mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_proc(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags, SYSFS_MASKOUT, MS_NODEV | MS_NOEXEC | MS_NOSUID);

    if (mount("proc", ctx->target, "proc", mountflags, ctx->data)) {
        fatalf("mount proc filesystem failed!\n");
        return -1;
    }
    return 0;
}

static int mount_tmpfs(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags, NBIND_MASKOUT, MS_NODEV);

    if (mount("tmpfs", ctx->target, "tmpfs", mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_devfs(const struct jail_mount_ctx *ctx)
{
    if (get_fstype(ctx->target) == TMPFS_MAGIC) {
        debugf("Unmounting old devfs...\n");
        if (try_umount(ctx->target)) {
            return -1;
        }
    }

    unsigned int mountflags = convert_flags(ctx->flags | JAIL_MNT_RW, SYSFS_MASKOUT, MS_NOEXEC | MS_NOSUID);

    if (mount("dev", ctx->target, "devtmpfs", mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_sysfs(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags, SYSFS_MASKOUT, MS_NODEV | MS_NOEXEC | MS_NOSUID);

    if (mount("sys", ctx->target, "sysfs", mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_udev(const struct jail_mount_ctx *ctx)
{
    if (get_fstype(ctx->target) == TMPFS_MAGIC) {
        debugf("Unmounting old devfs...\n");
        if (try_umount(ctx->target)) {
            return -1;
        }
    }
    unsigned int mountflags = convert_flags(ctx->flags | JAIL_MNT_RW, SYSFS_MASKOUT, MS_NOEXEC | MS_NOSUID);

    char optstr[4096], ptspath[PATH_MAX];
    if (ctx->data && strlen(ctx->data) > 0) {
        snprintf(optstr, sizeof(optstr), "mode=755,%s", ctx->data);
    } else {
        snprintf(optstr, sizeof(optstr), "mode=755");
    }
    if (mount("dev", ctx->target, "tmpfs", mountflags, optstr)) {
        return -1;
    }

    devf("Creating device node...\n");
    int rfd;
    if ((rfd = open(ctx->target, O_DIRECTORY | O_CLOEXEC)) < 0) {
        return -1;
    }
    int ret = 0;
    mode_t orig_umask = umask(0000);
    ret |= combine_path(ptspath, ctx->target, "/pts");
    ret |= mkdirat(rfd, "pts", 0755);
    ret |= mount("devpts", ptspath, "devpts", mountflags, "mode=620,ptmxmode=000");
    ret |= mknodat(rfd, "console", S_IFCHR | 0600, makedev(5, 1));
    ret |= mknodat(rfd, "ptmx", S_IFCHR | 0666, makedev(5, 2));
    ret |= mknodat(rfd, "full", S_IFCHR | 0666, makedev(1, 7));
    ret |= mknodat(rfd, "null", S_IFCHR | 0666, makedev(1, 3));
    ret |= mknodat(rfd, "tty", S_IFCHR | 0666, makedev(5, 0));
    ret |= mknodat(rfd, "random", S_IFCHR | 0666, makedev(1, 8));
    ret |= mknodat(rfd, "urandom", S_IFCHR | 0666, makedev(1, 9));
    ret |= mknodat(rfd, "zero", S_IFCHR | 0666, makedev(1, 5));
    ret |= symlinkat("/proc/self/fd", rfd, "fd");
    ret |= symlinkat("/proc/self/fd/0", rfd, "stdin");
    ret |= symlinkat("/proc/self/fd/1", rfd, "stdout");
    ret |= symlinkat("/proc/self/fd/2", rfd, "stderr");
    ret |= close(rfd);
    umask(orig_umask);

    return ret;
}

/* clang-format off */
static struct mount_operator mnt_ops[] = {
    { .name = "block", .fn = mount_disk },
    { .name = "loop", .fn = mount_loop },
    { .name = "bind", .fn = mount_bind },
    { .name = "tmpfs", .fn = mount_tmpfs },
    { .name = "proc", .fn = mount_proc },
    { .name = "sysfs", .fn = mount_sysfs },
    { .name = "devfs", .fn = mount_devfs },
    { .name = "udevfs", .fn = mount_udev },
    { .name = NULL, .fn = NULL },
};
/* clang-format on  */

int jail_mount(const char *root, const struct jail_mount_ctx *ctx)
{
    char path[PATH_MAX];
    if (root) {
        combine_path(path, root, ctx->target);
    } else {
        strncpy(path, ctx->target, sizeof(path));
    }

    struct jail_mount_ctx cctx;
    memcpy(&cctx, ctx, sizeof(struct jail_mount_ctx));
    cctx.target = path;

    int i = 0;
    while (mnt_ops[i].name) {
        if (strcmp(cctx.type, mnt_ops[i].name) == 0) {
            break;
        }
        i++;
    }

    if (mnt_ops[i].fn == NULL) {
        errno = EINVAL;
        return -1;
    }
    debugf("Mounting type %s on %s\n", cctx.type, cctx.target);
    return mnt_ops[i].fn(&cctx);
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
