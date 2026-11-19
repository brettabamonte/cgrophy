
#ifndef _TEST_H
#define _TEST_H

#include <assert.h>

typedef enum TestResult {
    FAIL,
    PASS
}TestResult;

typedef struct TestSuiteResult {
    int total;
    int pass;
    int fail;
}TestSuiteResult;

typedef struct TestSuite{
    char *name;
    TestSuiteResult (*run)(void);
}TestSuite;

static void test_result_callback(const char *name, TestResult test_result)
{
    if (test_result == PASS)
        printf("\033[32m%s\033[0m\n", name);
    else
        printf("\033[31m%s\033[0m\n", name);
}

static void run_test(const char *test_name, TestResult(*test)(void), TestSuiteResult *test_suite_result, void(*result_cb)(const char *, TestResult))
{
    TestResult test_result;

    assert(test);

    test_result = test();

    switch(test_result)
    {
        case PASS:
        {
            test_suite_result->pass++;
        }break;
        case FAIL:
        {
            test_suite_result->fail++;
        }break;
        default:
            assert(0); // TODO: handle this better. but failing loud is fine
    }

    result_cb(test_name, test_result);
}

#endif
