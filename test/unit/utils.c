#define _GNU_SOURCE
#include "cjail.h"
#include "fds.h"
#include "utils.h"

#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <criterion/parameterized.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>

#define STR_LEN 1024
#define CPUSTR_TEST_COUNT 5

/*
 *  Tests for testing cpuset_tostr()
 */

struct cpuset_pair {
    cpu_set_t input;
    char ans[STR_LEN];
};

void cpusetset(cpu_set_t *set, int cnt, ...)
{
    CPU_ZERO(set);
    va_list ap;
    va_start(ap, cnt);
    for (int i = 0; i < cnt; i++)
        CPU_SET(va_arg(ap, int), set);
    va_end(ap);
}

ParameterizedTestParameters(test_cpuset_tostr, tests)
{
    static struct cpuset_pair params[CPUSTR_TEST_COUNT];

    cpusetset(&params[0].input, 1, 0);
    strcpy(params[0].ans, "0");
    cpusetset(&params[1].input, 2, 0, 1);
    strcpy(params[1].ans, "0-1");
    cpusetset(&params[2].input, 7, 0, 1, 2, 4, 5, 9, 11);
    strcpy(params[2].ans, "0-2,4-5,9,11");
    cpusetset(&params[3].input, 5, 1, 4, 5, 6, 9);
    strcpy(params[3].ans, "1,4-6,9");
    cpusetset(&params[4].input, 5, 1, 3, 5, 7, 9);
    strcpy(params[4].ans, "1,3,5,7,9");
    printf("&params[0].ans = %p\n", params[0].ans);
    printf("params[0].ans = %s\n", params[0].ans);

    return cr_make_param_array(struct cpuset_pair, params, CPUSTR_TEST_COUNT);
}

ParameterizedTest(struct cpuset_pair *param, test_cpuset_tostr, tests)
{
    char str[STR_LEN];
    cr_log_info("&ans = %p\n", param->ans);
    cr_log_info("ans = %s\n", param->ans);
    int ret = cpuset_tostr(&param->input, str, sizeof(str));
    cr_assert_eq(strlen(param->ans), ret);
    cr_assert_str_eq(param->ans, str);
}

Test(test_cpuset_tostr, trunc_test_1)
{
    char str[10];
    cpu_set_t cpuset;
    cpusetset(&cpuset, 5, 1, 3, 5, 7, 11);
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
    cpusetset(&cpu1, 7, 0, 1, 3, 4, 5, 7, 11);
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
    cpusetset(&cpu1, 7, 1, 2, 3, 4, 5, 6, 11);
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
    for (int i = 0; i < rc; i++)
        root[i] = 'r';
    root[rc] = '\0';
    for (int i = 0; i < pc; i++)
        path[i] = 'p';
    path[pc] = '\0';
    for (int i = 0; i < PATH_MAX; i++) {
        if (i < rc)
            ans[i] = 'r';
        else if (i == rc)
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
