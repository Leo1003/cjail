#include "taskstats.h"

#include <unistd.h>

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
        return 0;	/* sendto() failure? */

        rep_len = recv(sd, &ans, sizeof(ans), 0);
    if (ans.n.nlmsg_type == NLMSG_ERROR ||
        (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
        return 0;

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) NLA_DATA(na);
    }
    return id;
}




