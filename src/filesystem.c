#include "filesystem.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

int get_filetype(char *path)
{
    struct stat st;
    if (stat(path, &st)) {
        return -1;
    }
    return (st.st_mode & S_IFMT);
}

int is_valid_source(char *source, int type)
{
    switch (type) {
        case FS_DISK: {
            mode_t t = get_filetype(source);
            return (t == S_IFBLK || t == S_IFREG);
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

static int mount_disk(char *source, char *target, unsigned int flags, char *option)
{
    char fstype[256];
    //TODO: resolve fstype from option
    /*uncompleted*/ return -1;
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    if (flags & FS_NOEXEC) mountflags |= MS_NOEXEC;
    if (!(flags & FS_SUID)) mountflags |= MS_NOSUID;
    if (mount(source, target, fstype, mountflags, option)) {
        return -1;
    }
    return 0;
}

static int mount_bind(char *source, char *target, unsigned int flags, char *option)
{
    unsigned int mountflags = 0;
    mountflags |= MS_NODEV;
    if (!(flags & FS_RW)) mountflags |= MS_RDONLY;
    if (flags & FS_NOEXEC) mountflags |= MS_NOEXEC;
    if (!(flags & FS_SUID)) mountflags |= MS_NOSUID;
    mountflags |= MS_REMOUNT;
    mountflags |= MS_BIND;
    if (mount(source, target, "", mountflags, option)) {
        return -1;
    }
    return 0;
}

static int mount_proc(char *target, char *option)
{
    if (mount("proc", target, "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, option)) {
        return -1;
    }
    return 0;
}

static int mount_tmpfs(char *target, unsigned int flags, char *option)
{
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

static int mount_devfs(char *target, char *option)
{
    if (mount("dev", target, "devtmpfs", MS_NOEXEC | MS_NOSUID, option)) {
        return -1;
    }
    return 0;
}

static int mount_sysfs(char *target, unsigned int flags, char *option)
{
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

inline static int jail_symlinkat(const char *root, const char *target, int fd, const char *name)
{
    char path[PATH_MAX];
    combine_path(path, root, target);
    return symlinkat(path, fd, name);
}

static int mount_udev(const char *root, const char *target, const char *option)
{
    if (mount("dev", target, "tmpfs", MS_NOEXEC | MS_NOSUID, option)) {
        return -1;
    }
    int rfd;
    if ((rfd = open(target, O_DIRECTORY | O_CLOEXEC)) < 0) {
        return -1;
    }
    mknodat(rfd, "console", S_IFCHR | 0600, makedev(5, 1));
    mknodat(rfd, "ptmx", S_IFCHR | 0666, makedev(5, 2));
    mknodat(rfd, "full", S_IFCHR | 0666, makedev(1, 7));
    mknodat(rfd, "tty", S_IFCHR | 0666, makedev(5, 0));
    mknodat(rfd, "random", S_IFCHR | 0666, makedev(1, 8));
    mknodat(rfd, "urandom", S_IFCHR | 0666, makedev(1, 9));
    mknodat(rfd, "zero", S_IFCHR | 0666, makedev(1, 5));
    jail_symlinkat(root, "/proc/self/fd", rfd, "fd");
    jail_symlinkat(root, "/proc/self/fd/0", rfd, "stdin");
    jail_symlinkat(root, "/proc/self/fd/1", rfd, "stdout");
    jail_symlinkat(root, "/proc/self/fd/2", rfd, "stderr");
    //TODO: /dev/pts
    return 0;
}

int jail_mount(char *source, char *root, char *target, unsigned int flags, char *option)
{
    char path[PATH_MAX];
    combine_path(path, root, target);
    if (!is_valid_source(source, flags & 0xF)) {
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
        case FS_BIND:
            ret = mount_bind(source, path, flags, option);
        case FS_TMP:
            ret = mount_tmpfs(path, flags, option);
        case FS_PROC:
            ret = mount_proc(path, option);
        case FS_DEV:
            ret = mount_devfs(path, option);
        case FS_SYS:
            ret = mount_sysfs(path, flags, option);
        case FS_UDEV:
            ret = mount_udev(root, path, option);
        default:
            errno = EINVAL;
            return -1;
    }
    return 0;
}

int jail_chroot(char *path, char *cdpath)
{
    if (path) {
        if (chroot(path) && chdir("/")) {
            PRINTERR("chroot");
            return -1;
        }
    }
    if (cdpath) {
        if (chdir(cdpath)) {
            PRINTERR("chdir");
            return -1;
        }
    }
    return 0;
}

int privatize_fs()
{
    if (mount("", "/", "", MS_REC | MS_PRIVATE, NULL)) {
        PRINTERR("privatize filesystem");
        return -1;
    }
    return 0;
}
