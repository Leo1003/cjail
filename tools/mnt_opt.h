#ifndef TOOLS_MNT_OPT_H
#define TOOLS_MNT_OPT_H
#include <cjail/filesystem.h>

int parse_mnt_flags(char *arg, struct jail_mount_ctx *mnt_ctx);
int parse_mnt_opt(const char *arg, struct jail_mount_list *mnt_list);

#endif
