#include "cjail.h"
#include "cgroup.h"
#include "utils.h"

#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static char cgroup_root[PATH_MAX] = CGROUP_DEFAULT_ROOT;

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
    char subpath[PATH_MAX], cgpath[PATH_MAX];
    combine_path(subpath, cgroup_root, subsystem);
    snprintf(cgpath, sizeof(char) * PATH_MAX, "%s/"CGROUP_NAME, subpath, getpid());
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

