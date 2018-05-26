#include "cjail.h"

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

START_TEST(basic_test_1)
{
    if (geteuid()) {
        ck_abort_msg("Should be tested as root!");
    }
    char *argv[] = { "/bin/echo", NULL };
    struct cjail_para para;
    struct cjail_result result;
    cjail_para_init(&para);
    para.argv = argv;
    ck_assert_int_eq(cjail_exec(&para, &result), 0);
    ck_assert_int_eq(result.info.si_code, CLD_EXITED);
    ck_assert_int_eq(result.info.si_status, EXIT_SUCCESS);
}
END_TEST

Suite* suite()
{
    Suite *s = suite_create("basic");
    TCase *t_basic = tcase_create("basic_test");

    tcase_add_test(t_basic, basic_test_1);

    suite_add_tcase(s, t_basic);
    return s;
}

int main()
{
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
