#ifndef SCMP_H
#define SCMP_H

#include "cjail.h"

int compile_seccomp(const struct cjail_para para, struct sock_fprog *bpf);

#endif
