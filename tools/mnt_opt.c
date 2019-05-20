#define _GNU_SOURCE
#include "mnt_opt.h"
#include "utils.h"
#include <cjail/filesystem.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Parser for mounting loop device or block device
// <source>=<chrooted_target>:<fstype>:<flags>:<data>
int parse_mnt_opt(const char *arg, struct jail_mount_list *mnt_list)
{
    struct jail_mount_ctx mnt_ctx;
    const size_t MNT_ARG_LEN = 4096;
    char arg_cp[MNT_ARG_LEN + 1];
    if (strlen(arg) > MNT_ARG_LEN) {
        perrf("Mounting argument too long\n");
        return -1;
    }
    strncpy(arg_cp, arg, sizeof(arg_cp));
    arg_cp[MNT_ARG_LEN] = '\0';
    memset(&mnt_ctx, 0, sizeof(mnt_ctx));

    char *path_part = strtok(arg_cp, ":");

    char *src = path_part, *target = NULL;
    if ((target = strchr(path_part, '=')) == NULL) {
        perrf("Mounting target not specified!\n");
        return -1;
    }
    *target = '\0';
    target++;
    // Target shouldn't be a zero-length string
    if (strlen(target) == 0) {
        perrf("Mounting target not specified!\n");
        return -1;
    }
    if (target[0] != '/') {
        perrf("Mounting target should be an absolute path!\n");
        return -1;
    }
    // '=' Should appear only once
    if (strchr(target, '=') != NULL) {
        perrf("\'=\' Should appear only once\n");
        return -1;
    }
    mnt_ctx.source = src;
    mnt_ctx.target = target;

    struct stat st;
    if (stat(src, &st)) {
        return -1;
    }
    if ((st.st_mode & S_IFMT) == S_IFREG) {
        mnt_ctx.type = "loop";
    } else if ((st.st_mode & S_IFMT) == S_IFBLK) {
        mnt_ctx.type = "block";
    } else {
        return -1;
    }

    mnt_ctx.fstype = strtok(NULL, ":");
    if (mnt_ctx.fstype == NULL || strlen(mnt_ctx.fstype) == 0) {
        perrf("file system type not specified!\n");
        return -1;
    }

    char* flags = strtok(NULL, ":");
    if (flags) {
        if (parse_mnt_flags(flags, &mnt_ctx)) {
            return -1;
        }
    }

    mnt_ctx.data = strtok(NULL, ":");
    return 0;
}

static inline int set_exclusive_flag(unsigned int *flags, unsigned int *exclflags, unsigned int f, bool set)
{
    if (*exclflags & JAIL_MNT_RW) {
        return -1;
    }
    *exclflags |= f;
    if (set) {
        *flags |= f;
    } else {
        *flags &= ~f;
    }
    return 0;
}

int parse_mnt_flags(char *arg, struct jail_mount_ctx *mnt_ctx)
{
    char *strtok_ptr, *token;
    unsigned int exclusiveflags = 0UL;
    mnt_ctx->flags = 0U;
    token = strtok_r(arg, " ,", &strtok_ptr);
    while (token != NULL) {
        int ret = 0;
        if (!strcmp(token, "rw")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_RW, true);
        } else if (!strcmp(token, "ro")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_RW, false);
        } else if (!strcmp(token, "suid")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_SUID, true);
        } else if (!strcmp(token, "nosuid")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_SUID, false);
        } else if (!strcmp(token, "noexec")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_NOEXEC, true);
        } else if (!strcmp(token, "exec")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_NOEXEC, false);
        } else if (!strcmp(token, "noatime")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_NOATIME, true);
        } else if (!strcmp(token, "atime")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_NOATIME, false);
        } else if (!strcmp(token, "sync")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_SYNC, true);
        } else if (!strcmp(token, "async")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_SYNC, false);
        } else if (!strcmp(token, "recursive")) {
            ret = set_exclusive_flag(&mnt_ctx->flags, &exclusiveflags, JAIL_MNT_REC, true);
        } else {
            perrf("Unknown flag: %s\n", token);
            return -1;
        }
        if (ret) {
            perrf("Conflicted flag: %s\n", token);
            return -1;
        }
    }
    return 0;
}
