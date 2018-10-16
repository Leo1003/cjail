#include "cjail.h"

#include <check.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

START_TEST(timing_test_1)
{
    char *argv[] = { "/bin/sleep", "3", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    ck_assert_int_eq(cjail_exec(&para, &result), 0);
    ck_assert_int_eq(result.info.si_code, CLD_EXITED);
    ck_assert_int_eq(result.info.si_status, EXIT_SUCCESS);
    ck_assert_int_eq(result.time.tv_sec, 3);
}
END_TEST

START_TEST(timing_test_2)
{
    srandom(time(NULL));
    int sec = (random() % 10 + 1);
    char sec_s[16];
    snprintf(sec_s, sizeof(sec_s), "%d", sec);
    fprintf(stderr, "Random timing test: %d sec\n", sec);
    char *argv[] = { "/bin/sleep", sec_s, NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    ck_assert_int_eq(cjail_exec(&para, &result), 0);
    ck_assert_int_eq(result.info.si_code, CLD_EXITED);
    ck_assert_int_eq(result.info.si_status, EXIT_SUCCESS);
    ck_assert_int_eq(result.time.tv_sec, sec);
}
END_TEST

START_TEST(timeout_test_1)
{
    char *argv[] = { "/bin/sleep", "3", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    para.lim_time.tv_sec = 2;
    ck_assert_int_eq(cjail_exec(&para, &result), 0);
    ck_assert_int_eq(result.info.si_code, CLD_KILLED);
    ck_assert_int_eq(result.info.si_status, SIGKILL);
    ck_assert_int_eq(result.timekill, 1);
    ck_assert_int_eq(result.time.tv_sec, 2);
}
END_TEST

Suite* suite()
{
    Suite *s = suite_create("timing");
    TCase *t_timing = tcase_create("timing_test");
    TCase *t_timeout = tcase_create("timeout_test");
    tcase_set_timeout(t_timing, 30);
    tcase_set_timeout(t_timeout, 30);

    tcase_add_test(t_timing, timing_test_1);
    tcase_add_test(t_timing, timing_test_2);

    tcase_add_test(t_timeout, timeout_test_1);

    suite_add_tcase(s, t_timing);
    suite_add_tcase(s, t_timeout);
    return s;
}

int main()
{
    if (geteuid()) {
        fprintf(stderr, "Should be tested as root!\n");
        fprintf(stderr, "Skip this test.\n");
        return EXIT_SUCCESS;
    }
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = suite();
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

