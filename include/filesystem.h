#ifndef _FILESYSTEM_H
#define _FILESYSTEM_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// clang-format off
#define JAIL_MNT_RW         0x00000001U
#define JAIL_MNT_SUID       0x00000002U
#define JAIL_MNT_NOEXEC     0x00000004U
#define JAIL_MNT_NOATIME    0x00000008U
#define JAIL_MNT_SYNC       0x00000010U
#define JAIL_MNT_REC        0x00000020U
// clang-format on

struct jail_mount_ctx {
    char *type;
    char *source, *target, *fstype;
    unsigned int flags;
    char *data;
};

struct jail_mount_list;

struct jail_mount_list *mnt_list_new();
void mnt_list_free(struct jail_mount_list *ml);
int mnt_list_add(struct jail_mount_list *ml, const struct jail_mount_ctx *ctx);
int mnt_list_clear(struct jail_mount_list *ml);

#define MNT_OPS_NAME_LEN 64
typedef int (*mnt_oper_fn)(const struct jail_mount_ctx *);
struct mnt_ops {
    char name[MNT_OPS_NAME_LEN];
    mnt_oper_fn fn;
    unsigned int mask;
    struct mnt_ops *next;
};

int mnt_ops_register(const struct mnt_ops *ops);
int mnt_ops_deregister(const char *name);
const struct mnt_ops *mnt_ops_find(const char *name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
