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

//TODO: Test closefrom()
int closefrom(int minfd)
{
    DIR *fddir = opendir("/proc/self/fd");
    if(!fddir)
        goto error;
    struct dirent *dent;
    while((dent = readdir(fddir)) != NULL)
    {
        int fd = atoi(dent->d_name);
        pdebugf("closing fd: %d\n", fd);
        if(fd > minfd && fd != dirfd(fddir))
        {
            IFERR(close(fd))
                goto error;
        }
    }
    closedir(fddir);
    return 0;

    error:
    PRINTERR("closefrom");
    return -1;
}

void parse_cpuset(const cpu_set_t* cpuset, char* cpumask)
{
    sprintf(cpumask, "");
    int s = -1, w = 0;
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
            sprintf(cpumask, "%s,", cpumask);
        if(c - s == 1)
            sprintf(cpumask, "%s%d", cpumask, s);
        else
            sprintf(cpumask, "%s%d-%d", cpumask, s, c - 1);
        s = -1;
    }
    pdebugf("parse_cpuset %s\n", cpumask);
}

//TODO: Test mkdir_r()
int mkdir_r(const char* path)
{
    int l;
    if((l = strlen(path)) == 0)
        return 0;
    struct stat st;
    IFERR(stat(path, &st))
    {
        if(strcmp(path, "."))
            return -2;
        char ppath[MAXPATHLEN];
        if(strlcpy(ppath, path, sizeof(ppath)) >= sizeof(ppath))
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        char *p = ppath + l - 1;
        if((p = strrchr(p, '/')) == NULL)
            strlcpy(ppath, ".", sizeof(ppath));
        else
            *p = '\0';

        int ret = mkdir_r(ppath);
        if(!ret)
            ret = mkdir(path, 0755);
        return ret;
    }
    else
    {
        if(S_ISDIR(st.st_mode))
            return 0;
        else
            return -2;
    }
}

char* combine_path(const char *root, const char *path)
{
    if(!root)
        return combine_path("/", path);

    char *r = malloc(MAXPATHLEN);
    if(!r)
        return NULL;

    char rtmp[MAXPATHLEN], ptmp[MAXPATHLEN];
    strlcpy(rtmp, root, sizeof(char) * MAXPATHLEN);
    strlcpy(ptmp, path, sizeof(char) * MAXPATHLEN);

    if(rtmp[strlen(root) - 1] == '/')
        strrmchr(rtmp, -1);
    if(ptmp[0] == '/')
        strrmchr(ptmp, 0);

    snprintf(r, sizeof(char) * MAXPATHLEN, "%s/%s", rtmp, ptmp);
    return r;
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
