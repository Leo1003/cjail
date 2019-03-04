#ifndef PROTOCOL_H
#define PROTOCOL_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include "cjail/cjail.h"
#include <sys/socket.h>
#include <sys/un.h>

#define RESULT_MAGIC    0x2E50
#define CRED_MAGIC      0xC2ED
#define READY_MAGIC     0x2EAD

int recv_magic(int un_sock);
int set_passcred(int un_sock);
ssize_t send_cred(int un_sock, const struct ucred *cred);
ssize_t recv_cred(int un_sock, struct ucred *cred);
ssize_t send_result(int un_sock, const struct cjail_result *result);
ssize_t recv_result(int un_sock, struct cjail_result *result);

#endif
