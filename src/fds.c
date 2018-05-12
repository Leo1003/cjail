#include "cjail.h"
#include "fds.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int setup_fd()
{
    int tmpfd[3] = { -1, -1, -1 };
    if (exec_para.para.redir_input) {
        close(STDIN_FILENO);
        IFERR (open(exec_para.para.redir_input, O_RDONLY)) {
            pdebugf("open(): %s\n", exec_para.para.redir_input);
            goto error;
        }
    }
    if (exec_para.para.redir_output) {
        close(STDOUT_FILENO);
        IFERR (open(exec_para.para.redir_output, O_WRONLY | O_CREAT | O_TRUNC, 0666)) {
            pdebugf("open(): %s\n", exec_para.para.redir_output);
            goto error;
        }
    }
    if (exec_para.para.redir_err) {
        close(STDERR_FILENO);
        IFERR (open(exec_para.para.redir_err, O_WRONLY | O_CREAT | O_TRUNC, 0666)) {
            pdebugf("open(): %s\n", exec_para.para.redir_err);
            goto error;
        }
    }

    /*
     * If users want to dup from standard fds, e.g., swapping stdout and stderr,
     * this will cause strange behaviors.
     * So we need to dup them all before closing them.
     */
    //TODO: Maybe we can have a better way to avoid it
    if (exec_para.para.fd_input != STDIN_FILENO) {
        if (!is_available_fd(exec_para.para.fd_input)) {
            errno = EBADF;
            goto error;
        }
        tmpfd[0] = dup(exec_para.para.fd_input);
        IFERR (tmpfd[0]) {
            pdebugf("dup(): %d\n", exec_para.para.fd_input);
            goto error;
        }
    }
    if (exec_para.para.fd_output != STDOUT_FILENO) {
        if (!is_available_fd(exec_para.para.fd_output)) {
            errno = EBADF;
            goto error;
        }
        tmpfd[1] = dup(exec_para.para.fd_output);
        IFERR (tmpfd[1]) {
            pdebugf("dup(): %d\n", exec_para.para.fd_output);
            goto error;
        }
    }
    if (exec_para.para.fd_err != STDERR_FILENO) {
        if (!is_available_fd(exec_para.para.fd_err)) {
            errno = EBADF;
            goto error;
        }
        tmpfd[2] = dup(exec_para.para.fd_err);
        IFERR (tmpfd[2]) {
            pdebugf("dup(): %d\n", exec_para.para.fd_err);
            goto error;
        }
    }

    if (tmpfd[0] > -1) {
        IFERR (dup2(tmpfd[0], STDIN_FILENO)) {
            pdebugf("dup2(): %d -> %d\n", tmpfd[0], STDIN_FILENO);
            goto error;
        }
        IFERR (close(tmpfd[0])) {
            goto error;
        }
    }
    if (tmpfd[1] > -1) {
        IFERR (dup2(tmpfd[1], STDOUT_FILENO)) {
            pdebugf("dup2(): %d -> %d\n", tmpfd[0], STDOUT_FILENO);
            goto error;
        }
        IFERR (close(tmpfd[1])) {
            goto error;
        }
    }
    if (tmpfd[2] > -1) {
        IFERR (dup2(tmpfd[2], STDERR_FILENO)) {
            pdebugf("dup2(): %d -> %d\n", tmpfd[0], STDERR_FILENO);
            goto error;
        }
        IFERR (close(tmpfd[2])) {
            goto error;
        }
    }

    if (!exec_para.para.preservefd)
        IFERR (closefrom(STDERR_FILENO + 1))
            return -1;
    return 0;

    error:
    PRINTERR("setup_fd");
    return -1;
}

int is_available_fd(int fd)
{
    int f = fcntl(fd, F_GETFD);
    if (f < 0 || f & FD_CLOEXEC) {
        return 0;
    }
    return 1;
}

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
