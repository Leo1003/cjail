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

//TODO: Test parse_cpuset()
void parse_cpuset(const cpu_set_t* cpuset, char* cpumask)
{
    int s = -1, w = 0;
    for(int c = 0; c <= CPU_COUNT(cpuset); c++)
    {
        if(c == CPU_COUNT(cpuset))
            goto e;

        if(CPU_ISSET(c, cpuset) && s == -1)
            s = c;
        else if(!CPU_ISSET(c, cpuset) && s > -1)
            goto e;

        continue;

        e:
        if(!w++)
            sprintf(cpumask, ",");
        if(c - s == 1)
            sprintf(cpumask, "%d", s);
        else
            sprintf(cpumask, "%d-%d", s, c - 1);
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

//TODO: Test combine_path()
char* combine_path(char *root, char *path)
{
    int l = 0;
    char *r = malloc(MAXPATHLEN);
    if(!r)
        return NULL;
    char *p = r;
    if(root)
    {
        l = strlen(root);
        strlcpy(r, root, sizeof(char) * MAXPATHLEN);
        if(root[l - 1] != '/')
            strlcpy(r + l, "/", sizeof(char) * (MAXPATHLEN - l));
        l = strlen(root);
        p += l;
    }
    strlcpy(p, path, sizeof(char) * (MAXPATHLEN - l));
    return r;
}
