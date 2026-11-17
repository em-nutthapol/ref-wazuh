/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/client-agent/notify_wrappers.h"

extern int g_ip_update_interval;
extern char g_host_ip[IPSIZE];
extern time_t g_host_ip_last_update;
extern bool g_host_ip_requested;
extern atomic_int_t g_host_ip_used;
int log_builder_update_host_ip(log_builder_t * builder);

// Setup / teardown

static int reset_host_ip_state(void **state) {
    *g_host_ip = '\0';
    g_host_ip_last_update = 0;
    g_host_ip_requested = false;
    atomic_int_set(&g_host_ip_used, 0);
    return 0;
}

// Helpers

/* Queue the mocks of one host IP request that reaches its source. */
static void expect_host_ip_request() {
#ifdef WIN32
    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, strdup("1.2.3.4"));
#else
    will_return(__wrap_control_check_connection, 16);
    will_return(__wrap_send, 7);
    will_return(__wrap_recv, 0);
#endif
}

static log_builder_t * init_builder(int interval) {
    will_return(__wrap_getDefine_Int, interval);
    log_builder_t * builder = log_builder_init(false);
    assert_non_null(builder);
    return builder;
}

// Tests

void test_log_builder(void **state)
{
    const char * PATTERN = "location: $(location), log: $(log), escaped: $(json_escaped_log)";
    const char * LOG = "Hello \"World\"";
    const char * LOCATION = "test";
    const char * EXPECTED_OUTPUT = "location: test, log: Hello \"World\", escaped: Hello \\\"World\\\"";

    will_return(__wrap_getDefine_Int, 60);

    int retval = 1;
    log_builder_t * builder = log_builder_init(false);

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION);

    assert_string_equal(output, EXPECTED_OUTPUT);

    free(output);
    log_builder_destroy(builder);
}

void test_log_builder_update(void **state)
{
    will_return(__wrap_getDefine_Int, 1);
    log_builder_t * builder = log_builder_init(false);
    assert_int_equal(g_ip_update_interval, 1);
    assert_non_null(builder);

#ifdef WIN32
    char * return_ip = "1.2.3.4";
    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, strdup(return_ip));
#elif defined __linux__ || defined __MACH__ || defined sun || defined FreeBSD || defined OpenBSD
    will_return(__wrap_control_check_connection, 16);
    will_return(__wrap_send, 7);
    will_return(__wrap_recv, 0);
#endif

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);
#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif
    log_builder_destroy(builder);
}

void test_log_builder_not_update(void **state) {
    will_return(__wrap_getDefine_Int, 0);

    log_builder_t * builder = log_builder_init(false);
    assert_int_equal(g_ip_update_interval, 0);
    assert_non_null(builder);

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_first_update_requests(void **state) {
    log_builder_t * builder = init_builder(60);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    assert_true(g_host_ip_requested);
#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif
    log_builder_destroy(builder);
}

// No mock is queued for the second update: a request would fail the test.
void test_log_builder_host_ip_not_refreshed_when_unused(void **state) {
    log_builder_t * builder = init_builder(60);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    g_host_ip_last_update = 0;
    assert_int_equal(log_builder_update_host_ip(builder), 0);

#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif
    log_builder_destroy(builder);
}

void test_log_builder_host_ip_refreshed_after_build_uses_it(void **state) {
    log_builder_t * builder = init_builder(60);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    char * output = log_builder_build(builder, "ip: $(host_ip)", "message", "location");
#ifdef WIN32
    assert_string_equal(output, "ip: 1.2.3.4");
#else
    assert_string_equal(output, "ip: 0.0.0.0");
#endif
    free(output);
    assert_int_equal(atomic_int_get(&g_host_ip_used), 1);

    g_host_ip_last_update = 0;
    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_other_params_do_not_mark_use(void **state) {
    log_builder_t * builder = init_builder(60);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    char * output = log_builder_build(builder, "$(hostname) $(location): $(log)", "message", "location");
    free(output);
    assert_int_equal(atomic_int_get(&g_host_ip_used), 0);

    g_host_ip_last_update = 0;
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_used_waits_for_interval(void **state) {
    log_builder_t * builder = init_builder(60);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);
    atomic_int_set(&g_host_ip_used, 1);

    // Same time as the first request: the interval has not elapsed.
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

#ifdef WIN32
void test_log_builder_host_ip_failed_lookup_counts_as_requested(void **state) {
    log_builder_t * builder = init_builder(60);

    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, NULL);
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    assert_true(g_host_ip_requested);
    assert_string_equal(builder->host_ip, "0.0.0.0");

    g_host_ip_last_update = 0;
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}
#else
void test_log_builder_host_ip_retries_until_control_available(void **state) {
    log_builder_t * builder = init_builder(60);

    will_return(__wrap_control_check_connection, -1);
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    assert_false(g_host_ip_requested);
    assert_int_equal(g_host_ip_last_update, 0);
    assert_string_equal(builder->host_ip, "0.0.0.0");

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    assert_true(g_host_ip_requested);
    log_builder_destroy(builder);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup(test_log_builder, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_not_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_first_update_requests, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_not_refreshed_when_unused, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_refreshed_after_build_uses_it, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_other_params_do_not_mark_use, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_used_waits_for_interval, reset_host_ip_state),
#ifdef WIN32
            cmocka_unit_test_setup(test_log_builder_host_ip_failed_lookup_counts_as_requested, reset_host_ip_state),
#else
            cmocka_unit_test_setup(test_log_builder_host_ip_retries_until_control_available, reset_host_ip_state),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
