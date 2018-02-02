#include "cjail.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

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
