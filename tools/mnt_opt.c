#define _GNU_SOURCE
#include "utils.h"
#include <cjail/filesystem.h>

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Parser for mounting source and target
// [$]<source>[=<chrooted_target>]
// '$' mean special source
int parse_src(char *path_arg, struct jail_mount_ctx *mnt_ctx)
{
    char *src = path_arg, *target = NULL;
    if ((target = strchr(path_arg, '=')) != NULL) {
        *target = '\0';
        target++;
        // Target shouldn't be a zero-length string
        if (strlen(target) == 0) {
            return -1;
        }
        // '=' Should appear only once
        if (strchr(target, '=') != NULL) {
            return -1;
        }
    }
    if (src[0] == '$') {
        src++;
        mnt_ctx->type = src;
        mnt_ctx->source = NULL;
        if (!strcmp(src, "tmpfs")) {
            if (!target) {
                mnt_ctx->target = "/tmp";
            } else {
                mnt_ctx->target = target;
            }
        } else if (!strcmp(src, "proc")) {
            if (!target) {
                mnt_ctx->target = "/proc";
            } else {
                mnt_ctx->target = target;
            }
        } else if (!strcmp(src, "sysfs")) {
            if (!target) {
                mnt_ctx->target = "/sys";
            } else {
                mnt_ctx->target = target;
            }
        } else if (!strcmp(src, "devfs") || !strcmp(src, "udevfs")) {
            if (!target) {
                mnt_ctx->target = "/dev";
            } else {
                mnt_ctx->target = target;
            }
        } else {
            return -1;
        }
    } else {
        struct stat st;
        if (stat(src, &st)) {
            return -1;
        }
        if ((st.st_mode & S_IFMT) == S_IFREG) {
            if (!target) {
                return -1;
            } else {
                mnt_ctx->target = target;
            }
            mnt_ctx->type = "loop";
        } else if ((st.st_mode & S_IFMT) == S_IFBLK) {
            if (!target) {
                return -1;
            } else {
                mnt_ctx->target = target;
            }
            mnt_ctx->type = "block";
        } else if ((st.st_mode & S_IFMT) == S_IFDIR) {
            if (!target) {
                mnt_ctx->target = src;
            } else {
                mnt_ctx->target = target;
            }
            mnt_ctx->type = "bind";
        } else {
            return -1;
        }
    }
    return 0;
}
