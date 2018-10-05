/**
 * @internal
 * @file utils.c
 * @brief useful functions source
 */
#include "cjail.h"
#include "logger.h"
#include "utils.h"

#include <bsd/string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>

int table_to_int(const table_int32* table, const char* str)
{
    int i = 0;
    while (table[i].name) {
        if (!strcmp(table[i].name, str)) {
            return table[i].value;
        }
        i++;
    }
    return table[i].value;
}

const char * table_to_str(const table_int32 *table, int value)
{
    int i = 0;
    while (table[i].name) {
        if (table[i].value == value) {
            return table[i].name;
        }
        i++;
    }
    return NULL;
}

int cpuset_tostr(const cpu_set_t* cpuset, char* str, size_t len)
{
    snprintf(str, len, "");
    int s = -1, w = 0, l = 0;
    for (int c = 0; c <= CPU_SETSIZE; c++) {
        if (c == CPU_SETSIZE && s > -1)
            goto e;

        if (CPU_ISSET(c, cpuset) && s == -1)
            s = c;
        else if (!CPU_ISSET(c, cpuset) && s > -1)
            goto e;
        continue;

    e:
        if (w++)
            l += snprintf(str + l, len - l, ",");
        if (l < 0 || l >= len)
            RETERR(ERANGE);

        if (c - s == 1)
            l += snprintf(str + l, len - l, "%d", s);
        else
            l += snprintf(str + l, len - l, "%d-%d", s, c - 1);
        s = -1;
        devf("cpumask = %s\n", str);
        if (l < 0 || l >= len)
            RETERR(ERANGE);
    }
    devf("parse_cpuset %s\n", str);
    return l;
}

static int readcpunum(const char *str, char **end_ptr)
{
    unsigned long num = strtoul(str, end_ptr, 10);
    if (str == *end_ptr)
        return -1;
    if (num >= CPU_SETSIZE)
        return -1;
    devf("readcpunum: %lu\n", num);
    return num;
}

int cpuset_parse(const char *str, cpu_set_t *cpuset)
{
    CPU_ZERO(cpuset);
    int l = strlen(str);
    const char *p = str;
    int s, e;

    while (p <= str + l) {
        char *n;
        s = readcpunum(p, &n);
        if (s < 0)
            RETERR(EINVAL);
        switch (*n) {
            case ',':
            case '\0':
                n++;
                e = s;
                break;
            case '-':
                n++;
                p = n;
                e = readcpunum(p, &n);
                if(e < 0)
                    RETERR(EINVAL);
                if(*n != ',' && *n != '\0')
                    RETERR(EINVAL);
                n++;
                break;
            default:
                RETERR(EINVAL);
        }
        if (e < s)
            RETERR(EINVAL);
        for (int i = s; i <= e; i++) {
            CPU_SET(i, cpuset);
        }
        p = n;
    }
    return 0;
}

int mkdir_r(const char* path)
{
    int l;
    if (!path || (l = strlen(path)) == 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (stat(path, &st)) {
        if (!strcmp(path, "."))
            return 0;
        char dpath[PATH_MAX];
        if (strlcpy(dpath, path, sizeof(dpath)) >= sizeof(dpath))
            RETERR(ENAMETOOLONG);
        char *ppath = dirname(dpath);

        int ret = mkdir_r(ppath);
        if (!ret)
            ret = mkdir(path, 0755);
        return ret;
    } else {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        } else {
            RETERR(ENOTDIR);
        }
    }
}

int combine_path(char *s, const char *root, const char *path)
{
    if (!root || !strcmp(root, ""))
        return combine_path(s, "/", path);
    if (!path || !strcmp(path, ""))
        return combine_path(s, root, "/");

    char rtmp[PATH_MAX], ptmp[PATH_MAX];
    strlcpy(rtmp, root, sizeof(char) * PATH_MAX);
    strlcpy(ptmp, path, sizeof(char) * PATH_MAX);

    if (rtmp[strlen(root) - 1] == '/')
        strrmchr(rtmp, -1);
    if (ptmp[0] == '/')
        strrmchr(ptmp, 0);

    snprintf(s, sizeof(char) * PATH_MAX, "%s/%s", rtmp, ptmp);
    return 0;
}

int strrmchr(char* str, int index)
{
    int l = strlen(str);
    if (index >= l || -index > l)
        return -1;
    if (index < 0)
        index += l;
    memmove(str + index, str + index + 1, l - index);
    return 0;
}

int setcloexec(int fd)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        PFTL("set close on exec flag");
        return -1;
    }
    return 0;
}

int pipe_c(int pipedes[2])
{
    return (pipe(pipedes) ||
        setcloexec(pipedes[0]) ||
        setcloexec(pipedes[1]));
}
