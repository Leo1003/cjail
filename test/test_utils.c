#include "cjail.h"
#include "utils.h"

#include <check.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>

#define STR_LEN 1024

/*
 *  Tests for testing parse_cpuset()
 */

START_TEST(test_parse_cpuset_1)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_str_eq("0", str);
}
END_TEST

START_TEST(test_parse_cpuset_2)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    CPU_SET(1, &cpuset);
    parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_str_eq("0-1", str);
}
END_TEST

START_TEST(test_parse_cpuset_3)
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
    parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_str_eq("0-2,4-5,9,11", str);
}
END_TEST

START_TEST(test_parse_cpuset_4)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(4, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(6, &cpuset);
    CPU_SET(9, &cpuset);
    parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_str_eq("1,4-6,9", str);
}
END_TEST

START_TEST(test_parse_cpuset_5)
{
    char str[STR_LEN];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(3, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(7, &cpuset);
    CPU_SET(9, &cpuset);
    parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_str_eq("1,3,5,7,9", str);
}
END_TEST

START_TEST(test_parse_cpuset_6)
{
    char str[10];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(3, &cpuset);
    CPU_SET(5, &cpuset);
    CPU_SET(7, &cpuset);
    CPU_SET(11, &cpuset);
    int ret = parse_cpuset(&cpuset, str, sizeof(str));
    ck_assert_int_eq(-1, ret);
    ck_assert_str_eq("1,3,5,7,1", str);
}
END_TEST

/*
 *  Tests for testing combine_path()
 */

START_TEST(test_combine_path_1)
{
    char str[PATH_MAX];
    combine_path(str, "/root", "/dev");
    ck_assert_str_eq("/root/dev", str);
}
END_TEST

START_TEST(test_combine_path_2)
{
    char str[PATH_MAX];
    combine_path(str, "/root", "dev");
    ck_assert_str_eq("/root/dev", str);
}
END_TEST

START_TEST(test_combine_path_3)
{
    char str[PATH_MAX];
    combine_path(str, "/", "/dev");
    ck_assert_str_eq("/dev", str);
}
END_TEST

START_TEST(test_combine_path_4)
{
    char str[PATH_MAX];
    combine_path(str, NULL, "/dev");
    ck_assert_str_eq("/dev", str);
}
END_TEST

START_TEST(test_combine_path_5)
{
    char str[PATH_MAX];
    combine_path(str, NULL, "dev");
    ck_assert_str_eq("/dev", str);
}
END_TEST

START_TEST(test_combine_path_6)
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
    ck_assert_str_eq(ans, str);
}
END_TEST

/*
 *  Tests for testing strrmchr()
 */

START_TEST(test_strrmchr_1)
{
    char str[STR_LEN] = "plogdhgjkahjgdfga";
    strrmchr(str, 2);
    ck_assert_str_eq("plgdhgjkahjgdfga", str);
}
END_TEST

START_TEST(test_strrmchr_2)
{
    char str[STR_LEN] = "plogdhgjkahjgdfga";
    strrmchr(str, -5);
    ck_assert_str_eq("plogdhgjkahjdfga", str);
}
END_TEST

START_TEST(test_strrmchr_3)
{
    char str[STR_LEN] = "pl";
    int ret = strrmchr(str, 2);
    ck_assert_int_eq(-1, ret);
}
END_TEST

START_TEST(test_strrmchr_4)
{
    char str[STR_LEN] = "pl";
    int ret = strrmchr(str, -3);
    ck_assert_int_eq(-1, ret);
}
END_TEST

/*
 *  libcheck suite setup
 */

Suite* suite_utils()
{
    Suite *s;
    TCase *t_cpuset, *t_combine, *t_strrmchr;
    s = suite_create("utils");

    t_cpuset = tcase_create("parse_cpuset");
    tcase_add_test(t_cpuset, test_parse_cpuset_1);
    tcase_add_test(t_cpuset, test_parse_cpuset_2);
    tcase_add_test(t_cpuset, test_parse_cpuset_3);
    tcase_add_test(t_cpuset, test_parse_cpuset_4);
    tcase_add_test(t_cpuset, test_parse_cpuset_5);
    tcase_add_test(t_cpuset, test_parse_cpuset_6);

    t_combine = tcase_create("combine_path");
    tcase_add_test(t_combine, test_combine_path_1);
    tcase_add_test(t_combine, test_combine_path_2);
    tcase_add_test(t_combine, test_combine_path_3);
    tcase_add_test(t_combine, test_combine_path_4);
    tcase_add_test(t_combine, test_combine_path_5);
    tcase_add_test(t_combine, test_combine_path_6);

    t_strrmchr = tcase_create("strrmchr");
    tcase_add_test(t_strrmchr, test_strrmchr_1);
    tcase_add_test(t_strrmchr, test_strrmchr_2);
    tcase_add_test(t_strrmchr, test_strrmchr_3);
    tcase_add_test(t_strrmchr, test_strrmchr_4);

    suite_add_tcase(s, t_cpuset);
    suite_add_tcase(s, t_combine);
    suite_add_tcase(s, t_strrmchr);
    return s;
}

int main(int argc, char *argv[])
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = suite_utils();
    sr = srunner_create(s);

#ifdef NDEBUG
    srunner_run_all(sr, CK_NORMAL);
#else
    srunner_run_all(sr, CK_VERBOSE);
#endif
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
