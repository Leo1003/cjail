#include "cjail.h"
#include "cgroup.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static char cgroup_root[PATH_MAX] = CGROUP_DEFAULT_ROOT;

static int get_cgpath(char *cgpath, const char* subsystem, const char *entry)
{
    char subpath[PATH_MAX];
    if (combine_path(subpath, cgroup_root, subsystem)) {
        return -1;
    }

    int ret = 0;
    if (entry) {
        ret = snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/"CGROUP_NAME"/%s",
                       subpath, getpid(), entry);
    } else {
        ret = snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/"CGROUP_NAME,
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

int cgroup_create(const char* subsystem)
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
    pdebugf("Failed at mkdir(): %s\n", cgpath);
    PRINTERR("create cgroup");
    return -1;
}

int cgroup_read(const char* subsystem, const char* name, const char* fmt, ...)
{
    int ret = -1;
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
    va_end(ap);
    fclose(fp);

err:
    if (ret < 0) {
        pdebugf("cgroup_read error: %s\n", cgpath);
        PRINTERR("read cgroup");
    }
    return ret;
}

int cgroup_write(const char* subsystem, const char* name, const char* fmt, ...)
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
        pdebugf("cgroup_write error: %s\n", cgpath);
        PRINTERR("write cgroup");
    }
    return ret;
}

int cgroup_open_tasks(const char* subsystem)
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
        pdebugf("cgroup_open_tasks error: %s\n", cgpath);
        PRINTERR("open cgroup tasks");
    }
    return fd;
}

int cgroup_destory(const char* subsystem)
{
    char cgpath[PATH_MAX];
    get_cgpath(cgpath, subsystem, NULL);

    if (rmdir(cgpath)) {
        pdebugf("cgroup_destory error: %s\n", cgpath);
        PRINTERR("destroy cgroup");
        return -1;
    }
    return 0;
}
