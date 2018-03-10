#include "cjail.h"
#include "utils.h"

#include <bsd/string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>

int closefrom(int minfd)
{
    DIR *fddir = opendir("/proc/self/fd");
    if(!fddir)
        goto error;
    struct dirent *dent;
    int dfd = dirfd(fddir);
    while((dent = readdir(fddir)) != NULL)
    {
        if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
            continue;
        int fd = strtol(dent->d_name, NULL, 10);
        if(fd >= minfd && fd != dfd)
        {
            pdebugf("closing fd: %d\n", fd);
            IFERR(close(fd))
                goto error_dir;
        }
    }
    closedir(fddir);
    return 0;

    error_dir:
    closedir(fddir);
    error:
    PRINTERR("closefrom");
    return -1;
}

int cpuset_tostr(const cpu_set_t* cpuset, char* str, size_t len)
{
    snprintf(str, len, "");
    int s = -1, w = 0, l = 0;
    for(int c = 0; c <= CPU_SETSIZE; c++)
    {
        if(c == CPU_SETSIZE && s > -1)
            goto e;

        if(CPU_ISSET(c, cpuset) && s == -1)
            s = c;
        else if(!CPU_ISSET(c, cpuset) && s > -1)
            goto e;
        continue;

        e:
        if(w++)
            l += snprintf(str + l, len - l, ",");
        if(l < 0 || l >= len)
            return -1;

        if(c - s == 1)
            l += snprintf(str + l, len - l, "%d", s);
        else
            l += snprintf(str + l, len - l, "%d-%d", s, c - 1);
        s = -1;
        pdebugf("cpumask = %s\n", str);
        if(l < 0 || l >= len)
            return -1;
    }
    pdebugf("parse_cpuset %s\n", str);
    return l;
}

static int readcpunum(const char *str, char **end_ptr)
{
    unsigned long num = strtoul(str, end_ptr, 10);
    if(str == *end_ptr)
        return -1;
    if(num >= CPU_SETSIZE)
        return -1;
    pdebugf("readcpunum: %lu\n", num);
    return num;
}

int cpuset_parse(const char *str, cpu_set_t *cpuset)
{
    CPU_ZERO(cpuset);
    int l = strlen(str);
    const char *p = str;
    int s, e;

    while(p <= str + l)
    {
        char *n;

        s = readcpunum(p, &n);
        if(s < 0)
            goto error;
        switch(*n)
        {
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
                    goto error;
                if(*n != ',' && *n != '\0')
                    goto error;
                n++;
                break;
            default:
                goto error;
        }
        if(e < s)
            goto error;
        for(int i = s; i <= e; i++)
            CPU_SET(i, cpuset);
        p = n;
    }

    return 0;

    error:
    errno = EINVAL;
    return -1;
}

int mkdir_r(const char* path)
{
    pdebugf("mkdir_r: %s: ", path);
    int l;
    if((l = strlen(path)) == 0)
        return 0;
    struct stat st;
    IFERR(stat(path, &st))
    {
        if(!strcmp(path, "."))
        {
            pdebugf("PWD\n");
            return 0;
        }
        char ppath[MAXPATHLEN];
        if(strlcpy(ppath, path, sizeof(ppath)) >= sizeof(ppath))
        {
            pdebugf("TooLong\n");
            errno = ENAMETOOLONG;
            return -errno;
        }
        char *p = ppath + l - 1;
        if((p = strrchr(ppath, '/')) == NULL)
            strlcpy(ppath, ".", sizeof(ppath));
        else
            *p = '\0';

        pdebugf("Recursive\n");
        int ret = mkdir_r(ppath);
        if(!ret)
        {
            pdebugf("mkdir: %s\n", path);
            ret = mkdir(path, 0755);
        }
        return ret;
    }
    else
    {
        if(S_ISDIR(st.st_mode))
        {
            pdebugf("Return\n");
            return 0;
        }
        else
        {
            pdebugf("Not dir\n");
            errno = ENOTDIR;
            return -errno;
        }
    }
}

int combine_path(char *s, const char *root, const char *path)
{
    if(!root || !strcmp(root, ""))
        return combine_path(s, "/", path);
    if(!path || !strcmp(path, ""))
        return combine_path(s, root, "/");

    char rtmp[PATH_MAX], ptmp[PATH_MAX];
    strlcpy(rtmp, root, sizeof(char) * PATH_MAX);
    strlcpy(ptmp, path, sizeof(char) * PATH_MAX);

    if(rtmp[strlen(root) - 1] == '/')
        strrmchr(rtmp, -1);
    if(ptmp[0] == '/')
        strrmchr(ptmp, 0);

    snprintf(s, sizeof(char) * PATH_MAX, "%s/%s", rtmp, ptmp);
    return 0;
}

int strrmchr(char* str, int index)
{
    int l = strlen(str);
    if(index >= l || -index > l)
        return -1;
    if(index < 0)
        index += l;
    memmove(str + index, str + index + 1, l - index);
    return 0;
}
