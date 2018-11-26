/**
 * @internal
 * @file filesystem.c
 * @brief file system mounting functions source
 */
#define _GNU_SOURCE
#include "filesystem.h"
#include "logger.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

int get_filetype(const char *path)
{
    struct stat st;
    if (stat(path, &st)) {
        return -1;
    }
    return (st.st_mode & S_IFMT);
}

static int is_valid_source(const char *source, int type)
{
    switch (type) {
        case FS_DISK: {
            mode_t t = get_filetype(source);
            /*
             * mounting disk image require loopback support
             * So, I don't want to unsupport it now...
             */
            // return (t == S_IFBLK || t == S_IFREG);
            return t == S_IFBLK;
        }
        case FS_BIND: {
            return (get_filetype(source) == S_IFDIR);
        }
        case FS_TMP:
        case FS_PROC:
        case FS_DEV:
        case FS_SYS:
        case FS_UDEV:
            return 1;
        default:
            return 0;
    }
    return 0;
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
    devf("a: %s ; b: %s\n", patha, pathb);
    devf("a.inode: %lu ; b.inode: %lu\n", sta.st_ino, stb.st_ino);
    return sta.st_ino == stb.st_ino;
}

int jail_symlinkat(const char *root, const char *target, int fd, const char *name)
{
    char path[PATH_MAX];
    combine_path(path, root, target);
    return symlinkat(path, fd, name);
}

static int mount_disk(const char *source, const char *target,
                      unsigned int flags, const char *option)
{
    devf("%s\n", __func__);
    char fstype[256], *optstr;
    char *p = strchrnul(option, '|');
    strncpy(fstype, option, MIN(sizeof(fstype), p - option));
    if (*p) {
        optstr = p + 1;
    } else {
        optstr = p;
    }
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    if (flags & FS_NOEXEC) mountflags |= MS_NOEXEC;
    if (!(flags & FS_SUID)) mountflags |= MS_NOSUID;
    if (mount(source, target, fstype, mountflags, optstr)) {
        return -1;
    }
    return 0;
}

static int mount_bind(const char *source, const char *target,
                      unsigned int flags, const char *option)
{
    devf("%s\n", __func__);
    if (mount(source, target, "", MS_BIND, "")) {
        return -1;
    }
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    if (flags & FS_NOEXEC) mountflags |= MS_NOEXEC;
    if (!(flags & FS_SUID)) mountflags |= MS_NOSUID;
    mountflags |= MS_REMOUNT;
    mountflags |= MS_BIND;
    if (mount("", target, "", mountflags, option)) {
        return -1;
    }
    return 0;
}

static int mount_proc(const char *target, const char *option)
{
    devf("%s\n", __func__);
    if (mount("proc", target, "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, option)) {
        fatalf("mount proc filesystem failed!\n");
        return -1;
    }
    return 0;
}

static int mount_tmpfs(const char *target, unsigned int flags, const char *option)
{
    devf("%s\n", __func__);
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    if (flags & FS_NOEXEC) mountflags |= MS_NOEXEC;
    if (!(flags & FS_SUID)) mountflags |= MS_NOSUID;
    if (mount("tmpfs", target, "tmpfs", mountflags, option)) {
        return -1;
    }
    return 0;
}

static int mount_devfs(const char *target, const char *option)
{
    devf("%s\n", __func__);
    if (is_same_inode("/dev", target)) {
        debugf("Unmounting old devfs...\n");
        if (umount2(target, MNT_DETACH | UMOUNT_NOFOLLOW)) {
            return -1;
        }
    }
    if (mount("dev", target, "devtmpfs", MS_NOEXEC | MS_NOSUID, option)) {
        return -1;
    }
    return 0;
}

static int mount_sysfs(const char *target, unsigned int flags, const char *option)
{
    devf("%s\n", __func__);
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    mountflags |= MS_NOEXEC;
    mountflags |= MS_NOSUID;
    if (mount("sys", target, "sysfs", mountflags, option)) {
        return -1;
    }
    return 0;
}

static int mount_udev(const char *root, const char *target, const char *option)
{
    devf("%s\n", __func__);
    if (is_same_inode("/dev", target)) {
        debugf("Unmounting old devfs...\n");
        if (umount2(target, MNT_DETACH | UMOUNT_NOFOLLOW)) {
            return -1;
        }
    }
    char optstr[4096], ptspath[PATH_MAX];
    if (strlen(option) > 0) {
        snprintf(optstr, sizeof(optstr), "mode=755,%s", option);
    } else {
        snprintf(optstr, sizeof(optstr), "mode=755");
    }
    if (mount("dev", target, "tmpfs", MS_NOEXEC | MS_NOSUID, optstr)) {
        return -1;
    }
    int rfd;
    if ((rfd = open(target, O_DIRECTORY | O_CLOEXEC)) < 0) {
        return -1;
    }
    int ret = 0;
    mode_t orig_umask = umask(0000);
    ret |= combine_path(ptspath, root, "/dev/pts");
    ret |= mkdirat(rfd, "pts", 0755);
    ret |= mount("devpts", ptspath, "devpts", MS_NOEXEC | MS_NOSUID, "mode=620,ptmxmode=000");
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

int jail_mount(const char *source, const char *root, const char *target,
               unsigned int flags, const char *option)
{
    char path[PATH_MAX];
    combine_path(path, root, target);
    if (!is_valid_source(source, flags & 0xF)) {
        errorf("invalid source!\n");
        errno = EINVAL;
        return -1;
    }
    if (mkdir_r(path)) {
        return -1;
    }
    int ret;
    switch (flags & 0xF) {
        case FS_DISK:
            ret = mount_disk(source, path, flags, option);
            break;
        case FS_BIND:
            ret = mount_bind(source, path, flags, option);
            break;
        case FS_TMP:
            ret = mount_tmpfs(path, flags, option);
            break;
        case FS_PROC:
            ret = mount_proc(path, option);
            break;
        case FS_DEV:
            ret = mount_devfs(path, option);
            break;
        case FS_SYS:
            ret = mount_sysfs(path, flags, option);
            break;
        case FS_UDEV:
            ret = mount_udev(root, path, option);
            break;
        default:
            errorf("invalid mount type!\n");
            errno = EINVAL;
            return -1;
    }
    return ret;
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
