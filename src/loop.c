/**
 * @internal
 * @file loop.c
 * @brief loopback device functions source
 */
#define _GNU_SOURCE
#include "loop.h"
#include "logger.h"
#include "utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int loop_open(int loop)
{
    char looppath[PATH_MAX];
    pathprintf(looppath, "/dev/loop%d", loop);
    return open(looppath, O_RDWR | O_CLOEXEC);
}

int loop_load(const char *path, int flags, struct loop_info *info)
{
    int imagefd;
    int openflags = ((flags & LOOP_LOAD_READONLY) ? O_RDONLY : O_RDWR) | O_CLOEXEC;

    if ((imagefd = open(path, openflags)) < 0) {
        return -1;
    }

    int ret = loop_attach(imagefd, flags, info);

    close(imagefd);
    return ret;
}

int loop_attach(int fd, int flags, struct loop_info *info)
{
    int ctrlfd, loopid, loopfd;
    if ((ctrlfd = open("/dev/loop-control", O_RDWR | O_CLOEXEC)) < 0) {
        return -1;
    }

    if ((loopid = ioctl(ctrlfd, LOOP_CTL_GET_FREE)) < 0) {
        loopid = -1;
        goto out_ctrl;
    }

    if ((loopfd = loop_open(loopid)) < 0) {
        loopid = -1;
        goto out_ctrl;
    }

    if (ioctl(loopfd, LOOP_SET_FD, fd) < 0) {
        loopid = -1;
        goto out_loop;
    }

    if (flags & LOOP_AUTO_DETACH) {
        struct loop_info li;
        memset(&li, 0, sizeof(li));
        li.lo_flags |= LO_FLAGS_AUTOCLEAR;
        if (ioctl(loopfd, LOOP_SET_STATUS, &li)) {
            loop_detach(loopid);
            loopid = -1;
            goto out_loop;
        }
    }

    if (info) {
        if (ioctl(loopfd, LOOP_GET_STATUS, info) < 0) {
            loop_detach(loopid);
            loopid = -1;
            goto out_loop;
        }
    }

out_loop:
    if (loopid == -1 || !(flags & LOOP_AUTO_DETACH)) {
        close(loopfd);
        close(ctrlfd);
        return loopid;
    }
out_ctrl:
    close(ctrlfd);
    return loopfd;
}

int loop_detach(int loop)
{
    int loopfd = loop_open(loop);
    if (loopfd < 0) {
        return -1;
    }

    int ret = ioctl(loopfd, LOOP_CLR_FD);

    close(loopfd);
    return ret;
}
