/**
 * @internal
 * @file taskstats.h
 * @brief taskstat resource statistics header
 */
#ifndef TASKSTATS_H
#define TASKSTATS_H

#include "utils.h"
#include <sched.h>
#include <time.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
// clang-format off
#define GENLMSG_DATA(glh)	    ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		    ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	    (len - NLA_HDRLEN)

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024
#define MAX_CPU_MASK    1024
// clang-format on

struct msgtemplate {
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[MAX_MSG_SIZE];
};

struct ts_socket {
    int socketfd, maskset;
    unsigned short familyid;
    char cpumask[MAX_CPU_MASK];
};

int taskstats_create(struct ts_socket *s);
int taskstats_setcpuset(struct ts_socket *s, cpu_set_t *cpuset);
int taskstats_setpid(struct ts_socket *s, pid_t pid);
int taskstats_getstats(struct ts_socket *s, struct taskstats *ts);
int taskstats_destory(struct ts_socket *s);

#endif
