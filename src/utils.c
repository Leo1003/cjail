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
