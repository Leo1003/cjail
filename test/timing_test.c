#include "cjail.h"

#include <criterion/criterion.h>
#include <criterion/assert.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    if (geteuid()) {
        cr_skip_test("Not running as root!\n");
    }
}

TestSuite(timing_test, .init = setup, .timeout = 12);

Test(timing_test, test_1)
{
    char *argv[] = { "/bin/sleep", "3", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    cr_assert_eq(cjail_exec(&para, &result), 0);
    cr_expect_eq(result.info.si_code, CLD_EXITED);
    cr_expect_eq(result.info.si_status, EXIT_SUCCESS);
    cr_expect_eq(result.time.tv_sec, 3);
}

Test(timing_test, test_2)
{
    srandom(time(NULL));
    int sec = (random() % 10 + 1);
    char sec_s[16];
    snprintf(sec_s, sizeof(sec_s), "%d", sec);
    cr_log_info("Random timing test: %d sec\n", sec);
    char *argv[] = { "/bin/sleep", sec_s, NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    cr_assert_eq(cjail_exec(&para, &result), 0);
    cr_expect_eq(result.info.si_code, CLD_EXITED);
    cr_expect_eq(result.info.si_status, EXIT_SUCCESS);
    cr_expect_eq(result.time.tv_sec, sec);
}

TestSuite(timeout_test, .init = setup, .timeout = 10);

Test(timeout_test, test_1)
{
    char *argv[] = { "/bin/sleep", "3", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    para.lim_time.tv_sec = 2;
    cr_assert_eq(cjail_exec(&para, &result), 0);
    cr_expect_eq(result.info.si_code, CLD_KILLED);
    cr_expect_eq(result.info.si_status, SIGKILL);
    cr_expect_eq(result.timekill, 1);
    cr_expect_eq(result.time.tv_sec, 2);
}
