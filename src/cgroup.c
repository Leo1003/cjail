/**
 * @internal
 * @file cgroup.c
 * @brief cgroup system operation source
 */
#include "cgroup.h"
#include "cjail.h"
#include "config.h"
#include "logger.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static char cgroup_root[PATH_MAX] = CFG_CGROOT;

static int get_cgpath(char *cgpath, const char *subsystem, const char *entry)
{
    char subpath[PATH_MAX];
    if (combine_path(subpath, cgroup_root, subsystem)) {
        return -1;
    }

    int ret = 0;
    if (entry) {
        ret = snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/" CFG_CGNAME "/%s",
                       subpath, getpid(), entry);
    } else {
        ret = snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/" CFG_CGNAME,
                       subpath, getpid());
    }
    if (ret >= PATH_MAX) {
        errno = ENAMETOOLONG;
        ret = -1;
    }
    return ret;
}

int cgroup_set_root(const char *path)
{
    struct stat st;
    if (strlen(path) >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (stat(path, &st)) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    int ret = snprintf(cgroup_root, sizeof(char) * PATH_MAX, "%s", path) < 0;
    return (ret < 0) ? -1 : 0;
}

int cgroup_create(const char *subsystem)
{
    char cgpath[PATH_MAX];
    if (get_cgpath(cgpath, subsystem, NULL) < 0 ||
        mkdir(cgpath, 0755)) {
        goto err;
    }
    return 0;

err:
    if (errno == EEXIST)
        return 0;
    errorf("Failed to mkdir at: %s\n", cgpath);
    PFTL("create cgroup");
    return -1;
}

int cgroup_read(const char *subsystem, const char *name, const char *fmt, ...)
{
    int ret = -1, is_eof = 0;
    va_list ap;
    char cgpath[PATH_MAX];
    if (get_cgpath(cgpath, subsystem, name) < 0) {
        goto err;
    }

    FILE *fp = fopen(cgpath, "r");
    if (!fp)
        goto err;

    va_start(ap, fmt);
    ret = vfscanf(fp, fmt, ap);
    is_eof = feof(fp);
    va_end(ap);
    fclose(fp);

err:
    if (ret < 0 && !is_eof) {
        errorf("Failed to read: %s\n", cgpath);
        PFTL("read cgroup");
    }
    return ret;
}

int cgroup_write(const char *subsystem, const char *name, const char *fmt, ...)
{
    int ret = -1;
    va_list ap;
    char cgpath[PATH_MAX];
    if (get_cgpath(cgpath, subsystem, name) < 0) {
        goto err;
    }

    FILE *fp = fopen(cgpath, "w");
    if (!fp)
        goto err;

    va_start(ap, fmt);
    ret = vfprintf(fp, fmt, ap);
    va_end(ap);
    fflush(fp);
    fclose(fp);

err:
    if (ret < 0) {
        errorf("Failed to write: %s\n", cgpath);
        PFTL("write cgroup");
    }
    return ret;
}

int cgroup_open_tasks(const char *subsystem)
{
    char cgpath[PATH_MAX];
    int fd = -1;
    if (get_cgpath(cgpath, subsystem, "tasks") < 0) {
        goto err;
    }

    fd = open(cgpath, O_RDWR);
    if (setcloexec(fd)) {
        if (errno != EBADF) {
            close(fd);
        }
        fd = -1;
    }
err:
    if (fd < 0) {
        errorf("Failed to open tasks file: %s\n", cgpath);
        PFTL("open cgroup tasks");
    }
    return fd;
}

int cgroup_destory(const char *subsystem)
{
    char cgpath[PATH_MAX];
    get_cgpath(cgpath, subsystem, NULL);

    if (rmdir(cgpath)) {
        errorf("Failed to destory cgroup: %s\n", cgpath);
        PFTL("destroy cgroup");
        return -1;
    }
    return 0;
}
