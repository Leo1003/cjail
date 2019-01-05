#include "filesystem.h"
#include "logger.h"
#include "loop.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <unistd.h>

unsigned int convert_flags(unsigned int flags)
{
    unsigned int sflags = 0;

    if (!(flags & JAIL_MNT_RW)) sflags |= MS_RDONLY;
    if (flags & JAIL_MNT_NOEXEC) sflags |= MS_NOEXEC;
    if (!(flags & JAIL_MNT_SUID)) sflags |= MS_NOSUID;
    if (flags & JAIL_MNT_SYNC) sflags |= (MS_SYNCHRONOUS | MS_DIRSYNC);
    if (flags & JAIL_MNT_NOATIME) sflags |= MS_NOATIME;
    if (flags & JAIL_MNT_REC) sflags |= MS_REC;

    return sflags;
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

static int mount_disk(const struct jail_mount_ctx *ctx)
{
    if (get_filetype(ctx->source) != S_IFBLK) {
        errno = EINVAL;
        return -1;
    }

    unsigned int mountflags = convert_flags(ctx->flags) | MS_NODEV;

    if (mount(ctx->source, ctx->target, ctx->fstype, mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_bind(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags) | MS_BIND | MS_NODEV;

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
    unsigned int mountflags = convert_flags(ctx->flags) | MS_NODEV | MS_NOEXEC | MS_NOSUID;

    if (mount("proc", ctx->target, "proc", mountflags, ctx->data)) {
        fatalf("mount proc filesystem failed!\n");
        return -1;
    }
    return 0;
}

static int mount_tmpfs(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags) | MS_NODEV;

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

    unsigned int mountflags = convert_flags(ctx->flags | JAIL_MNT_RW) | MS_NOEXEC | MS_NOSUID;

    if (mount("dev", ctx->target, "devtmpfs", mountflags, ctx->data)) {
        return -1;
    }
    return 0;
}

static int mount_sysfs(const struct jail_mount_ctx *ctx)
{
    unsigned int mountflags = convert_flags(ctx->flags) | MS_NODEV | MS_NOEXEC | MS_NOSUID;

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
    unsigned int mountflags = convert_flags(ctx->flags | JAIL_MNT_RW) | MS_NOEXEC | MS_NOSUID;

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

#define BLOCK_MASK (JAIL_MNT_RW | JAIL_MNT_SUID | JAIL_MNT_NOEXEC | JAIL_MNT_NOATIME | JAIL_MNT_SYNC)
#define BIND_MASK (JAIL_MNT_RW | JAIL_MNT_SUID | JAIL_MNT_NOEXEC | JAIL_MNT_NOATIME | JAIL_MNT_SYNC | JAIL_MNT_REC)
#define SYS_MASK (JAIL_MNT_RW | JAIL_MNT_NOATIME)
#define DEV_MASK (JAIL_MNT_NOATIME)

const struct mnt_ops builtin_mount_ops[] = {
    { .name = "block", .fn = mount_disk, .mask = BLOCK_MASK },
    { .name = "loop", .fn = mount_loop, .mask = BLOCK_MASK },
    { .name = "bind", .fn = mount_bind, .mask = BIND_MASK },
    { .name = "tmpfs", .fn = mount_tmpfs, .mask = BLOCK_MASK },
    { .name = "proc", .fn = mount_proc, .mask = SYS_MASK },
    { .name = "sysfs", .fn = mount_sysfs, .mask = SYS_MASK },
    { .name = "devfs", .fn = mount_devfs, .mask = DEV_MASK },
    { .name = "udevfs", .fn = mount_udev, .mask = DEV_MASK },
};
#define builtin_mount_ops_len (sizeof(builtin_mount_ops) / sizeof(struct mnt_ops))

static void builtin_mount_register() __attribute__((constructor));
static void builtin_mount_register()
{
    for (int i = 0; i < builtin_mount_ops_len; i++) {
        mnt_ops_register(&builtin_mount_ops[i]);
    }
    return;
}
