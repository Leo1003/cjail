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

inline static void get_cgpath(char *cgpath, const char* subsystem)
{
    char subpath[PATH_MAX];
    combine_path(subpath, cgroup_root, subsystem);
    snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/"CGROUP_NAME, subpath, getpid());
}

int cgroup_set_root(const char *path)
{
    struct stat st;
    if(strlen(path) >= PATH_MAX)
        return -1;
    IFERR(stat(path, &st))
        return -1;
    if(!S_ISDIR(st.st_mode))
        return -1;
    snprintf(cgroup_root, sizeof(char) * PATH_MAX, "%s", path);
    return 0;
}

int cgroup_create(const char* subsystem)
{
    char cgpath[PATH_MAX];
    get_cgpath(cgpath, subsystem);
    IFERR(mkdir(cgpath, 0755))
        goto error;
    return 0;

    error:
    if(errno == EEXIST)
        return 0;
    pdebugf("Failed at mkdir(): %s\n", cgpath);
    PRINTERR("create cgroup");
    return -1;
}

int cgroup_read(const char* subsystem, const char* name, const char* fmt, ...)
{
    va_list ap;
    char cgpath[PATH_MAX], settingpath[PATH_MAX];
    get_cgpath(cgpath, subsystem);
    snprintf(settingpath, sizeof(char) * PATH_MAX, "%s/%s", cgpath, name);

    FILE *fp = fopen(settingpath, "r");
    if(!fp)
        goto error;

    int ret;
    errno = 0;
    va_start(ap, fmt);
    IFERR((ret = vfscanf(fp, fmt, ap)))
    {
        if(errno)
        {
            pdebugf("cgroup_read error: %s\n", settingpath);
            PRINTERR("read cgroup");
        }
    }
    va_end(ap);
    fclose(fp);
    return ret;

    error:
    pdebugf("cgroup_read error: %s\n", settingpath);
    PRINTERR("read cgroup");
    return -1;
}

int cgroup_write(const char* subsystem, const char* name, const char* fmt, ...)
{
    va_list ap;
    char cgpath[PATH_MAX], settingpath[PATH_MAX];
    get_cgpath(cgpath, subsystem);
    snprintf(settingpath, sizeof(char) * PATH_MAX, "%s/%s", cgpath, name);

    FILE *fp = fopen(settingpath, "w");
    if(!fp)
        goto error;

    int ret;
    errno = 0;
    va_start(ap, fmt);
    IFERR((ret = vfprintf(fp, fmt, ap)))
    {
        if(errno)
        {
            pdebugf("cgroup_write error: %s\n", settingpath);
            PRINTERR("write cgroup");
        }
    }
    va_end(ap);
    fclose(fp);
    return ret;

    error:
    pdebugf("cgroup_write error: %s\n", settingpath);
    PRINTERR("write cgroup");
    return -1;
}

int cgroup_open_tasks(const char* subsystem)
{
    char cgpath[PATH_MAX], taskspath[PATH_MAX];
    int fd;
    get_cgpath(cgpath, subsystem);
    snprintf(taskspath, sizeof(char) * PATH_MAX, "%s/tasks", cgpath);

    IFERR((fd = open(taskspath, O_RDWR)))
    {
        pdebugf("cgroup_open_tasks error: %s\n", taskspath);
        PRINTERR("open cgroup tasks");
    }
    IFERR(fcntl(fd, F_SETFD, FD_CLOEXEC))
    {
        PRINTERR("set close on exec flag");
        return -1;
    }
    return fd;
}

int cgroup_destory(const char* subsystem)
{
    char cgpath[PATH_MAX];
    get_cgpath(cgpath, subsystem);

    IFERR(rmdir(cgpath))
    {
        pdebugf("cgroup_destory error: %s\n", cgpath);
        PRINTERR("destroy cgroup");
        return -1;
    }
    return 0;
}
