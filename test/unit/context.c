#include "cjail.h"

#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <stdlib.h>
#include <unistd.h>

const struct cjail_ctx inited_ctx = {
    .preservefd = 0,
    .sharenet = 0,
    .fd_input = STDIN_FILENO,
    .fd_output = STDOUT_FILENO,
    .fd_error = STDERR_FILENO,
    .redir_input = NULL,
    .redir_output = NULL,
    .redir_error = NULL,
    .argv = NULL,
    .environ = NULL,
    .chroot = NULL,
    .workingDir = NULL,
    .cgroup_root = NULL,
    .cpuset = NULL,
    .uid = 65534,
    .gid = 65534,
    .rlim_as = 0,
    .rlim_core = -1,
    .rlim_nofile = 0,
    .rlim_fsize = 0,
    .rlim_proc = 0,
    .rlim_stack = 0,
    .cg_rss = 0,
    .lim_time = { 0 },
    .seccomp_cfg = NULL,
    .mount_cfg = NULL,
};

Test(context, test_init)
{
    struct cjail_ctx ctx;
    cjail_ctx_init(&ctx);
    cr_expect_eq(memcmp(&ctx, &inited_ctx, sizeof(struct cjail_ctx)), 0);
}
