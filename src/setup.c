#include "cjail.h"
#include "setup.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

int setup_fs()
{
    struct stat st;
    IFERR(mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL))
        goto error;
    if(exec_para->chroot)
    {
        IFERR(chroot(exec_para->chroot))
            goto error;
    }
    IFERR(stat("/proc", &st))
    {
        IFERR(mkdir("/proc", 0755))
            goto error;
    }
    IFERR(mount("proc", "/proc", "proc", 0, ""))
        goto error;
    if(exec_para->workingDir)
    {
        IFERR(chdir(exec_para->workingDir))
            goto error;
    }
    return 0;

    error:
    PRINTERR("setup_fs");
    return -1;
}

int setup_fd()
{
    if (exec_para->fd_input)
    {
        close(STDIN_FILENO);
        IFERR(open(exec_para->fd_input, O_RDONLY))
            goto error;
    }
    if (exec_para->fd_output)
    {
        close(STDOUT_FILENO);
        IFERR(open(exec_para->fd_output, O_WRONLY | O_CREAT | O_TRUNC, 0666))
            goto error;
    }
    if (exec_para->fd_err)
    {
        close(STDERR_FILENO);
        IFERR(open(exec_para->fd_err, O_WRONLY | O_CREAT | O_TRUNC, 0666))
            goto error;
    }
    else
    {
        IFERR(dup2(STDOUT_FILENO, STDERR_FILENO))
            goto error;
    }
    IFERR(closefrom(STDERR_FILENO))
        return -1;
    return 0;

    error:
    PRINTERR("setup_fd");
    return -1;
}
