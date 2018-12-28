#define _GNU_SOURCE
#include "assets.h"

#include "cjail.h"
#include "filesystem.h"
#include "loop.h"

#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <unistd.h>

#define MOUNT_POINT "/mnt"
#define README_PATH MOUNT_POINT"/README.txt"
#define TESTDATA_PATH MOUNT_POINT"/TESTDATA.txt"

const char *readme_data = "The filesystem is successfully mounted!\n";

void setup()
{
    if (geteuid()) {
        cr_skip_test("Not running as root!\n");
    }
    if (unshare(CLONE_NEWNS)) {
        cr_assert_fail("Failed to unshare the mount namespace.\n");
    }
    if (privatize_fs()) {
        cr_assert_fail("Failed to privatize the mount namespace.\n");
    }
}

static void assert_file_exist(const char *path)
{
    cr_assert_eq(access(path, F_OK), 0, "File %s not exist!\n", path);
}

static void test_filedata(const char *path)
{
    assert_file_exist(path);
    FILE *fp = fopen(path, "r");
    cr_assert_not_null(fp, "Failed to open the file: %s\n", path);
    cr_expect_file_contents_eq_str(fp, readme_data, "README content not match!\n");
    fclose(fp);
}

__fsword_t get_fstype(const char *path)
{
    struct statfs stf;
    if (statfs(path, &stf)) {
        return -1;
    }
    return stf.f_type;
}

TestSuite(mount_test, .init = setup);

Test(mount_test, test_loop)
{
    assert_file_exist(DISKIMAGE1_PATH);

    struct jail_mount_ctx ctx = {
        .type = "loop",
        .source = DISKIMAGE1_PATH,
        .target = MOUNT_POINT,
        .fstype = "ext4",
        .flags = JAIL_MNT_NOATIME,
        .data = NULL
    };

    cr_assert_neq(jail_mount(NULL, &ctx), -1, "Failed to mount loopback image: %s\n", strerror(errno));
    cr_expect_eq(get_fstype(MOUNT_POINT), EXT4_SUPER_MAGIC, "File system type not match!\n");

    test_filedata(README_PATH);
}

Test(mount_test, test_tmpfs)
{
    struct jail_mount_ctx ctx = {
        .type = "tmpfs",
        .source = NULL,
        .target = MOUNT_POINT,
        .fstype = NULL,
        .flags = JAIL_MNT_RW,
        .data = NULL
    };

    cr_assert_neq(jail_mount(NULL, &ctx), -1, "Failed to mount filesystem: %s\n", strerror(errno));
    cr_expect_eq(get_fstype(MOUNT_POINT), TMPFS_MAGIC, "File system type not match!\n");

    FILE *fp = fopen(README_PATH, "w");
    cr_assert_not_null(fp, "Failed to open the file: %s\n", README_PATH);
    fprintf(fp, "%s", readme_data);
    fclose(fp);

    test_filedata(README_PATH);
}

Test(mount_test, test_bind)
{
    struct jail_mount_ctx ctx = {
        .type = "bind",
        .source = ASSETS_DIR,
        .target = MOUNT_POINT,
        .fstype = NULL,
        .flags = 0,
        .data = NULL
    };

    cr_assert_neq(jail_mount(NULL, &ctx), -1, "Failed to mount filesystem: %s\n", strerror(errno));

    test_filedata(TESTDATA_PATH);
}
