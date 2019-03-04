#define _GNU_SOURCE
#include "protocol.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAGIC_LENGTH    (sizeof(unsigned int))

union cmsg_ucred {
    struct cmsghdr cmh;
    unsigned char buf[CMSG_SPACE(sizeof(struct ucred))]; /* Space large enough to hold a ucred structure */
};

int set_passcred(int un_sock)
{
    int val = 1;
    return setsockopt(un_sock, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val));
}

inline static int send_magic(int un_sock, const unsigned int magic)
{
    return (send(un_sock, &magic, MAGIC_LENGTH, 0) < 0 ? -1 : 0);
}

int recv_magic(int un_sock)
{
    unsigned int magic;
    ssize_t ret = recv(un_sock, &magic, MAGIC_LENGTH, MSG_TRUNC);
    if (ret < 0) {
        return -1;
    }
    if (ret != MAGIC_LENGTH) {
        errno = EBADMSG;
        return -1;
    }
    return magic;
}

ssize_t send_cred(int un_sock, const struct ucred *cred)
{
    struct msghdr msgh;
    struct iovec iov;
    unsigned int magic = CRED_MAGIC;
    union cmsg_ucred cmsg;
    struct cmsghdr *chdr;
    /* We still need some data to send, we use magic code again! */
    iov.iov_base = &magic;
    iov.iov_len = MAGIC_LENGTH;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_control = &cmsg;
    msgh.msg_controllen = sizeof(cmsg);

    chdr = CMSG_FIRSTHDR(&msgh);
    chdr->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    chdr->cmsg_level = SOL_SOCKET;
    chdr->cmsg_type = SCM_CREDENTIALS;
    if (cred) {
        memcpy(CMSG_DATA(chdr), cred, sizeof(struct ucred));
    } else {
        struct ucred *ucp = (struct ucred *) CMSG_DATA(chdr);;
        ucp->pid = getpid();
        ucp->uid = getuid();
        ucp->gid = getgid();
    }
    /* Send magic code first(This is the first magic code) */
    if (send_magic(un_sock, CRED_MAGIC) < 0) {
        return -1;
    }
    /* Here will have magic code again as body data */
    return sendmsg(un_sock, &msgh, 0);
}

ssize_t recv_cred(int un_sock, struct ucred *cred)
{
    struct msghdr msgh;
    struct iovec iov;
    unsigned int data;
    union cmsg_ucred cmsg;
    struct cmsghdr *chdr;
    ssize_t ret = 0;

    iov.iov_base = &data;
    iov.iov_len = MAGIC_LENGTH;

    cmsg.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
    cmsg.cmh.cmsg_level = SOL_SOCKET;
    cmsg.cmh.cmsg_type = SCM_CREDENTIALS;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_control = &cmsg;
    msgh.msg_controllen = sizeof(cmsg);

    /* Receive data */
    if ((ret = recvmsg(un_sock, &msgh, 0)) < 0) {
        goto out;
    }
    chdr = CMSG_FIRSTHDR(&msgh);
    /* Do some checking... */
    if (chdr == NULL || chdr->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
        errno = EBADMSG;
        ret = -1;
        goto out;
    }
    if (chdr->cmsg_level != SOL_SOCKET) {
        errno = EBADMSG;
        ret = -1;
        goto out;
    }
    if (chdr->cmsg_type != SCM_CREDENTIALS) {
        errno = EBADMSG;
        ret = -1;
        goto out;
    }
    /* Drop data if NULL */
    if (cred) {
        memcpy(cred, CMSG_DATA(chdr), sizeof(struct ucred));
    }
out:
    return ret;
}

ssize_t send_result(int un_sock, const struct cjail_result *result)
{
    if (!result) {
        errno = EINVAL;
        return -1;
    }

    if (send_magic(un_sock, RESULT_MAGIC) < 0) {
        return -1;
    }

    return send(un_sock, result, sizeof(struct cjail_result), 0);
}

ssize_t recv_result(int un_sock, struct cjail_result *result)
{
    struct cjail_result buf;

    ssize_t ret = recv(un_sock, &buf, sizeof(struct cjail_result), 0);
    if (ret < 0) {
        goto out;
    }
    /* Do some checking... */
    if (ret != sizeof(struct cjail_result)) {
        errno = EBADMSG;
        ret = -1;
        goto out;
    }
    /* Drop data if NULL */
    if (result) {
        memcpy(result, &buf, sizeof(struct cjail_result));
    }
out:
    return ret;
}

int send_ready(int un_sock)
{
    return send_magic(un_sock, READY_MAGIC);
}

int wait_for_ready(int un_sock)
{
    unsigned int data;
    ssize_t ret = 0;

    while (1) {
        ret = recv(un_sock, &data, MAGIC_LENGTH, MSG_PEEK | MSG_TRUNC);
        if (ret < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                usleep(100000);
                continue;
            } else {
                break;
            }
        }
        if (ret == MAGIC_LENGTH && data == READY_MAGIC) {
            /* Consume data */
            ret = recv(un_sock, &data, MAGIC_LENGTH, 0);
            break;
        } else {
            errno = EBADMSG;
            ret = -1;
            break;
        }
    }

    return ret;
}
