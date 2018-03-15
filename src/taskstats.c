#include "cjail.h"
#include "taskstats.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>

/* getdelays.c
 *
 * Utility to get per-pid and per-tgid delay accounting statistics
 * Also illustrates usage of the taskstats interface
 *
 * Copyright (C) Shailabh Nagar, IBM Corp. 2005
 * Copyright (C) Balbir Singh, IBM Corp. 2006
 * Copyright (c) Jay Lan, SGI. 2006
 *
 * Compile with
 *	gcc -I/usr/src/linux/include getdelays.c -o getdelays
 */
static int create_nl_socket(int protocol)
{
    int fd;
    struct sockaddr_nl local;

    fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if(fd < 0)
        return -1;

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;

    if(bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
        goto error;

    return fd;

    error:
    close(fd);
    return -1;
}

static int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
             __u8 genl_cmd, __u16 nla_type,
             void *nla_data, int nla_len)
{
    struct nlattr *na;
    struct sockaddr_nl nladdr;
    int r, buflen;
    char *buf;

    struct msgtemplate msg;
    memset(&msg, 0, sizeof(msg));

    msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    msg.n.nlmsg_type = nlmsg_type;
    msg.n.nlmsg_flags = NLM_F_REQUEST;
    msg.n.nlmsg_seq = 0;
    msg.n.nlmsg_pid = nlmsg_pid;
    msg.g.cmd = genl_cmd;
    msg.g.version = 0x1;
    na = (struct nlattr *) GENLMSG_DATA(&msg);
    na->nla_type = nla_type;
    na->nla_len = nla_len + 1 + NLA_HDRLEN;
    memcpy(NLA_DATA(na), nla_data, nla_len);
    msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    buf = (char *) &msg;
    buflen = msg.n.nlmsg_len;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    while((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr, sizeof(nladdr))) < buflen)
    {
        if(r > 0)
        {
            buf += r;
            buflen -= r;
        }
        else if(errno != EAGAIN)
            return -1;
    }
    return 0;
}

static int get_family_id(int sd)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } ans;

    int id = 0, rc;
    struct nlattr *na;
    int rep_len;

    char name[64];
    strcpy(name, TASKSTATS_GENL_NAME);
    rc = send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
                  CTRL_ATTR_FAMILY_NAME, (void *)name,
                  strlen(TASKSTATS_GENL_NAME)+1);
    if (rc < 0)
    {
        pdebugf("send_cmd() failed\n");
        return 0;
    }	/* sendto() failure? */

    rep_len = recv(sd, &ans, sizeof(ans), 0);
    if (ans.n.nlmsg_type == NLMSG_ERROR ||
        (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
        {
            pdebugf("recv() failed\n");
            pdebugf("NLMSG_ERROR: %d\n", ans.n.nlmsg_type == NLMSG_ERROR);
            pdebugf("rep_len: %d\n", rep_len);
            struct nlmsgerr* err = NLMSG_DATA(&ans);
            pdebugf("Error: %d\n", err->error);
            errno = err->error;
            return 0;
        }

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) NLA_DATA(na);
    }
    return id;
}

int taskstats_create(struct ts_socket *s)
{
    memset(s, 0, sizeof(*s)); //empty socket object
    IFERR(s->socketfd = create_nl_socket(NETLINK_GENERIC))
    {
        PRINTERR("create netlink socket");
        return -1;
    }
    IFERR(setcloexec(s->socketfd))
        return -1;
    pdebugf("Created netlink socket: fd %d\n", s->socketfd);
    if(!(s->familyid = get_family_id(s->socketfd)))
    {
        PRINTERR("get family id");
        return -1;
    }
    pdebugf("Got family id: %d\n", s->familyid);

    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    IFERR(setsockopt(s->socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
    {
        PRINTERR("set socket timeout");
    }
    return 0;
}

int taskstats_setcpuset(struct ts_socket* s, cpu_set_t* cpuset)
{
    IFERR(cpuset_tostr(cpuset, s->cpumask, sizeof(s->cpumask)))
    {
        PRINTERR("parse_cpuset");
        return -1;
    }
    pdebugf("Setting cpumask to: %s\n", s->cpumask);
    IFERR(send_cmd(s->socketfd, s->familyid, getpid(), TASKSTATS_CMD_GET,
                   TASKSTATS_CMD_ATTR_REGISTER_CPUMASK, s->cpumask, strlen(s->cpumask) + 1))
    {
        PRINTERR("taskstats_setcpuset");
        return -1;
    }
    s->maskset = 1;
    return 0;
}

int taskstats_setpid(struct ts_socket* s, pid_t pid)
{
    IFERR(send_cmd(s->socketfd, s->familyid, getpid(), TASKSTATS_CMD_GET,
        TASKSTATS_CMD_ATTR_PID, &pid, sizeof(pid)))
    {
        PRINTERR("taskstats_setpid\n");
        return -1;
    }
    return 0;
}

int taskstats_getstats(struct ts_socket* s, struct taskstats* ts)
{
    struct msgtemplate msg;
    int rep_len = recv(s->socketfd, &msg, sizeof(msg), 0);
    if (rep_len < 0) {
        switch(errno)
        {
            case EAGAIN:
            case ETIMEDOUT:
            case EBUSY:
                break;
            default:
                PRINTERR("getstats (recv error)");
                break;
        }
        return -2;
    }
    if (msg.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&msg.n), rep_len)) {
        struct nlmsgerr* err = NLMSG_DATA(&msg);
        errno = -(err->error);
        PRINTERR("getstats (taskstats error)");
        return -1;
    }

    rep_len = GENLMSG_PAYLOAD(&msg.n);
    struct nlattr* na = (struct nlattr*) GENLMSG_DATA(&msg);
    int len = 0;
    while (len < rep_len)
    {
        len += NLA_ALIGN(na->nla_len);
        switch (na->nla_type)
        {
            case TASKSTATS_TYPE_AGGR_TGID:
            case TASKSTATS_TYPE_AGGR_PID:
            {
                int aggr_len = NLA_PAYLOAD(na->nla_len);
                int len2 = 0;
                /* For nested attributes, na follows */
                na = (struct nlattr*) NLA_DATA(na);
                while (len2 < aggr_len)
                {
                    switch (na->nla_type) {
                        case TASKSTATS_TYPE_PID: break;
                        case TASKSTATS_TYPE_TGID: break;
                        case TASKSTATS_TYPE_STATS:
                            memcpy(ts, (struct taskstats*) NLA_DATA(na), sizeof(struct taskstats));
                            return 0;
                            break;
                        default:
                            perrf("Unknown nested nla_type %d\n", na->nla_type);
                            break;
                    }
                    len2 += NLA_ALIGN(na->nla_len);
                    na = (struct nlattr*) ((char*) na + len2);
                }
            }
            break;
            default:
                perrf("Unknown nla_type %d\n", na->nla_type);
                break;
        }
        na = (struct nlattr*) (GENLMSG_DATA(&msg) + len);
    }
    errno = EFAULT;
    return -2;
}

int taskstats_destory(struct ts_socket* s)
{
    if(s->maskset)
    {
        IFERR(send_cmd(s->socketfd, s->familyid, getpid(), TASKSTATS_CMD_GET,
                          TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
                          s->cpumask, strlen(s->cpumask) + 1))
            PRINTERR("deregister cpumask");
        // nonfatal error
    }
    IFERR(close(s->socketfd))
    {
        PRINTERR("close socket");
        return -1;
    }
    memset(s, 0, sizeof(*s)); //empty socket object
    return 0;
}
