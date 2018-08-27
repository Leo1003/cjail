#include "cjail.h"
#include "fds.h"
#include "logger.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int reopen(int fd, const char *path, char type)
{
    int nfd = -1;
    if (path) {
        close(fd);
        int flags = 0;
        switch (type) {
            case 'r':
                flags = O_RDONLY;
                break;
            case 'w':
                flags = O_WRONLY | O_CREAT | O_TRUNC;
                break;
            case '+':
                flags = O_RDWR | O_CREAT | O_TRUNC;
                break;
            case 'a':
                flags = O_WRONLY | O_APPEND;
            default:
                errno = EINVAL;
                return -1;
        }
        nfd = open(path, flags, 0666);
        if (nfd < 0) {
            fatalf("Failed to reopen: %s\n", path);
            return -1;
        } else if (nfd != fd) {
            if (dup2(nfd, fd) < 0) {
                PFTL("dup2 target fd");
                return -1;
            }
            if (close(nfd)) {
                PFTL("close temporary fd");
                return -1;
            }
        }
    }
    return 0;
}

int tfddup(int fd, int stdfd, int *tfd, int *clo)
{
    if (fd != stdfd) {
        if (!is_valid_fd(fd)) {
            errno = EBADF;
            return -1;
        }
        if (fd <= STDERR_FILENO) {
            *tfd = dup(fd);
            if (*tfd < 0) {
                fatalf("Failed to dup fd %d: %s\n", fd, strerror(errno));
                return -1;
            }
            *clo = 1;
        } else {
            *tfd = fd;
        }
    }
    return 0;
}

int applyfd(int fd, int to, int clos)
{
    if (fd > -1) {
        if (dup2(fd, to) < 0) {
            fatalf("Failed to dup fd %d -> %d: %s\n", fd, to, strerror(errno));
            return -1;
        }
        if (clos && close(fd) < 0) {
            return -1;
        }
    }
    return 0;
}

int setup_fd(const struct cjail_para para)
{
    int tfd[3] = { -1, -1, -1 };
    int clo[3] = { 0, 0, 0 };

    /*
     * Swap logger output to prevent logs writing into redirected fds
     */
    if (swap_log_file()) {
        PFTL("swap log file");
        return -1;
    }

    if (reopen(STDIN_FILENO, para.redir_input, 'r')) {
        goto error;
    }
    if (reopen(STDOUT_FILENO, para.redir_output, 'w')) {
        goto error;
    }
    if (reopen(STDERR_FILENO, para.redir_error, 'w')) {
        goto error;
    }

    /*
     * If users want to dup from standard fds, e.g., swapping stdout and stderr,
     * this will cause strange behaviors.
     * So we need to dup them before closing them.
     */
    if (tfddup(para.fd_input, STDIN_FILENO, &tfd[0], &clo[0])) {
        goto error;
    }
    if (tfddup(para.fd_output, STDOUT_FILENO, &tfd[1], &clo[1])) {
        goto error;
    }
    if (tfddup(para.fd_error, STDERR_FILENO, &tfd[2], &clo[2])) {
        goto error;
    }

    if (applyfd(tfd[0], STDIN_FILENO, clo[0])) {
        goto error;
    }
    if (applyfd(tfd[1], STDOUT_FILENO, clo[1])) {
        goto error;
    }
    if (applyfd(tfd[2], STDERR_FILENO, clo[2])) {
        goto error;
    }

    if (!para.preservefd)
        if (closefrom(STDERR_FILENO + 1) < 0)
            return -1;
    return 0;

    error:
    PFTL("setup_fd");
    return -1;
}

int is_valid_fd(int fd)
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
    if (!fddir)
        goto error;
    struct dirent *dent;
    int dfd = dirfd(fddir);
    while ((dent = readdir(fddir)) != NULL) {
        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
            continue;
        int fd = strtol(dent->d_name, NULL, 10);
        if (fd >= minfd && fd != dfd && is_valid_fd(fd)) {
            devf("closing fd: %d\n", fd);
            if (close(fd) && errno != EBADF) {
                goto error_dir;
            }
        }
    }
    closedir(fddir);
    return 0;

    error_dir:
    closedir(fddir);
    error:
    PFTL("closefrom");
    return -1;
}
