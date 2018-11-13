#define _GNU_SOURCE
#include "cjail.h"
#include "fds.h"
#include "utils.h"

#include <criterion/criterion.h>
#include <criterion/assert.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>

#define STR_LEN 1024

/*
 *  Tests for testing cpuset_tostr()
 */

Test(test_cpuset_tostr, test_1)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_str_eq("0", str);
}

Test(test_cpuset_tostr, test_2)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    CPU_SET(1, &cpuset);
    cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_str_eq("0-1", str);
}

Test(test_cpuset_tostr, test_3)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(2, &cpuset);
    CPU_SET(4, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(9, &cpuset);
    CPU_SET(11, &cpuset);
    cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_str_eq("0-2,4-5,9,11", str);
}

Test(test_cpuset_tostr, test_4)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(4, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(6, &cpuset);
    CPU_SET(9, &cpuset);
    cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_str_eq("1,4-6,9", str);
}

Test(test_cpuset_tostr, test_5)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(3, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(7, &cpuset);
    CPU_SET(9, &cpuset);
    cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_str_eq("1,3,5,7,9", str);
}

Test(test_cpuset_tostr, test_6)
{
    char str[10];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(3, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(7, &cpuset);
    CPU_SET(11, &cpuset);
    int ret = cpuset_tostr(&cpuset, str, sizeof(str));
    cr_assert_eq(-1, ret);
    cr_assert_str_eq("1,3,5,7,1", str);
}

/*
 *  Tests for testing combine_path()
 */

Test(test_cpuset_parse, test_1)
{
    cpu_set_t cpu1, cpu2;
    CPU_ZERO(&cpu1);
    CPU_SET(0, &cpu1);
    CPU_SET(1, &cpu1);
    CPU_SET(3, &cpu1);
    CPU_SET(4, &cpu1);
    CPU_SET(5, &cpu1);
    CPU_SET(7, &cpu1);
    CPU_SET(11, &cpu1);
    cr_assert_eq(cpuset_parse("0,1,3-5,7,11", &cpu2), 0);
    cr_assert_neq(CPU_EQUAL(&cpu1, &cpu2), 0);
}

Test(test_cpuset_parse, test_2)
{
    cpu_set_t cpu1, cpu2;
    CPU_ZERO(&cpu1);
    CPU_SET(0, &cpu1);
    CPU_SET(1, &cpu1);
    CPU_SET(3, &cpu1);
    CPU_SET(4, &cpu1);
    CPU_SET(5, &cpu1);
    CPU_SET(7, &cpu1);
    CPU_SET(11, &cpu1);
    cr_assert_eq(cpuset_parse("0 ,1,3-5,7,11", &cpu2), -1);
}

Test(test_cpuset_parse, test_3)
{
    cpu_set_t cpu1, cpu2;
    CPU_ZERO(&cpu1);
    CPU_SET(1, &cpu1);
    CPU_SET(2, &cpu1);
    CPU_SET(3, &cpu1);
    CPU_SET(4, &cpu1);
    CPU_SET(5, &cpu1);
    CPU_SET(6, &cpu1);
    CPU_SET(11, &cpu1);
    cr_assert_eq(cpuset_parse("1-6,11", &cpu2), 0);
    cr_assert_neq(CPU_EQUAL(&cpu1, &cpu2), 0);
}

/*
 *  Tests for testing combine_path()
 */

Test(test_combine_path, test_1)
{
    char str[PATH_MAX];
    combine_path(str, "/root", "/dev");
    cr_assert_str_eq("/root/dev", str);
}

Test(test_combine_path, test_2)
{
    char str[PATH_MAX];
    combine_path(str, "/root", "dev");
    cr_assert_str_eq("/root/dev", str);
}

Test(test_combine_path, test_3)
{
    char str[PATH_MAX];
    combine_path(str, "/", "/dev");
    cr_assert_str_eq("/dev", str);
}

Test(test_combine_path, test_4)
{
    char str[PATH_MAX];
    combine_path(str, NULL, "/dev");
    cr_assert_str_eq("/dev", str);
}

Test(test_combine_path, test_5)
{
    char str[PATH_MAX];
    combine_path(str, NULL, "dev");
    cr_assert_str_eq("/dev", str);
}

Test(test_combine_path, test_6)
{
    char str[PATH_MAX];
    char root[PATH_MAX], path[PATH_MAX], ans[PATH_MAX];
    const int rc = 3072, pc = 2048;
    for(int i = 0; i < rc; i++)
        root[i] = 'r';
    root[rc] = '\0';
    for(int i = 0; i < pc; i++)
        path[i] = 'p';
    path[pc] = '\0';
    for(int i = 0; i < PATH_MAX; i++)
    {
        if(i < rc)
            ans[i] = 'r';
        else if(i == rc)
            ans[i] = '/';
        else
            ans[i] = 'p';
    }
    ans[PATH_MAX - 1] = '\0';

    combine_path(str, root, path);
    cr_assert_str_eq(ans, str);
}

Test(test_combine_path, test_7)
{
    char str[PATH_MAX];
    combine_path(str, "", "dev");
    cr_assert_str_eq("/dev", str);
}

Test(test_combine_path, test_8)
{
    char str[PATH_MAX];
    combine_path(str, "", "");
    cr_assert_str_eq("/", str);
}

Test(test_combine_path, test_9)
{
    char str[PATH_MAX];
    combine_path(str, "/new_root", "");
    cr_assert_str_eq("/new_root/", str);
}

/*
 *  Tests for testing strrmchr()
 */

Test(test_strrmchr, test_1)
{
    char str[STR_LEN] = "plogdhgjkahjgdfga";
    strrmchr(str, 2);
    cr_assert_str_eq("plgdhgjkahjgdfga", str);
}

Test(test_strrmchr, test_2)
{
    char str[STR_LEN] = "plogdhgjkahjgdfga";
    strrmchr(str, -5);
    cr_assert_str_eq("plogdhgjkahjdfga", str);
}

Test(test_strrmchr, test_3)
{
    char str[STR_LEN] = "pl";
    int ret = strrmchr(str, 2);
    cr_assert_eq(-1, ret);
}

Test(test_strrmchr, test_4)
{
    char str[STR_LEN] = "pl";
    int ret = strrmchr(str, -3);
    cr_assert_eq(-1, ret);
}
