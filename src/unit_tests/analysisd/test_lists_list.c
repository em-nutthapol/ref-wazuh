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

#include "../../headers/shared.h"
#include "../../analysisd/rules.h"
#include "../../analysisd/cdb/cdb.h"
#include "../../analysisd/cdb/cdb_make.h"
#include "../../analysisd/analysisd.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void os_remove_cdblist(ListNode **l_node);
void os_remove_cdbrules(ListRule **l_rule);
ListNode *OS_FindList(const char *listname, ListNode **l_node);
void OS_ListLoadRules(ListNode **l_node, ListRule **lrule);

void __real_OSMatch_FreePattern(OSMatch *reg);

/* setup/teardown */

typedef struct address_value_state {
    char cdb_path[PATH_MAX];
    ListNode *node;
    ListRule *rule;
} address_value_state;

/* Builds a CDB list with a full address and a subnet prefix entry, and an
 * address_match_key_value rule over it whose check_value is "funny". */
static int setup_address_match_value(void **state) {
    address_value_state *data;
    os_calloc(1, sizeof(address_value_state), data);

    snprintf(data->cdb_path, sizeof(data->cdb_path), "/tmp/test_lists_list_XXXXXX");
    int fd = mkstemp(data->cdb_path);
    if (fd < 0) {
        os_free(data);
        return -1;
    }

    FILE *fp = fdopen(fd, "w+");
    struct cdb_make cdbm;
    cdb_make_start(&cdbm, fp);
    cdb_make_add(&cdbm, "10.10.10.10", strlen("10.10.10.10"), "funny", strlen("funny"));
    cdb_make_add(&cdbm, "172.16.0.1", strlen("172.16.0.1"), "serious", strlen("serious"));
    cdb_make_add(&cdbm, "192.168.", strlen("192.168."), "funny", strlen("funny"));
    cdb_make_add(&cdbm, "10.20.", strlen("10.20."), "serious", strlen("serious"));
    cdb_make_finish(&cdbm);
    fclose(fp);

    os_calloc(1, sizeof(ListNode), data->node);
    os_strdup(data->cdb_path, data->node->cdb_filename);
    os_strdup("ssh-watch-list", data->node->txt_filename);
    data->node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    os_calloc(1, sizeof(ListRule), data->rule);
    data->rule->loaded = 1;
    data->rule->lookup_type = LR_ADDRESS_MATCH_VALUE;
    data->rule->field = RULE_SRCIP;
    data->rule->db = data->node;
    data->rule->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    os_calloc(1, sizeof(OSMatch), data->rule->matcher);
    if (!OSMatch_Compile("funny", data->rule->matcher, 0)) {
        return -1;
    }

    *state = data;
    return 0;
}

static int teardown_address_match_value(void **state) {
    address_value_state *data = *state;

    if (data->node->loaded) {
        cdb_free(&data->node->cdb);
        close(data->node->cdb.fd);
    }
    unlink(data->cdb_path);

    __real_OSMatch_FreePattern(data->rule->matcher);
    os_free(data->rule->matcher);
    os_free(data->rule);
    os_free(data->node->cdb_filename);
    os_free(data->node->txt_filename);
    os_free(data->node);
    os_free(data);
    return 0;
}

/* wraps */

void __wrap_OSMatch_FreePattern(OSMatch *reg) {
    return;
}

/* tests */

/* os_remove_cdblist */
void test_os_remove_cdblist_OK(void **state)
{
    ListNode *l_node;
    os_calloc(1,sizeof(ListNode), l_node);
    os_calloc(1,sizeof(ListNode), l_node->cdb_filename);
    os_calloc(1,sizeof(char*), l_node->txt_filename);

    os_remove_cdblist(&l_node);

}

/* os_remove_cdbrules */
void test_os_remove_cdbrules_OK(void **state)
{
    ListRule *l_rule;
    os_calloc(1,sizeof(ListRule), l_rule);
    os_calloc(1,sizeof(ListRule), l_rule->matcher);
    os_calloc(1,sizeof(char*), l_rule->dfield);
    os_calloc(1,sizeof(char*), l_rule->filename);
    os_remove_cdbrules(&l_rule);

}

/* OS_FindList */
void test_OS_FindList_dont_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    ListNode * retval;

    os_calloc(1, sizeof(ListNode), node);
    node->next = NULL;
    node->txt_filename = "not_list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_null(retval);

    os_free(node);
}

void test_OS_FindList_empty_node(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node = NULL;
    ListNode * retval;

    retval = OS_FindList(list, &node);

    assert_null(retval);
}

void test_OS_FindList_txt_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

void test_OS_FindList_cdb_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

/* OS_ListLoadRules */
void test_OS_ListLoadRules_rule_null_check(void ** state) {
    ListNode * l_node = (ListNode *) 1;
    ListRule * lrule = NULL;

    OS_ListLoadRules(&l_node, &lrule);
}

void test_OS_ListLoadRules_list_checked(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("test_file");

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
}

void test_OS_ListLoadRules_list_checked_and_load (void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("list_test.cbd");

    /* OS_FindList */
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    OS_ListLoadRules(&node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
    os_free(node);
}

void test_OS_ListLoadRules_already_load(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 1;

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule);
    os_free(lrule);
}

/* OS_DBSearch with address_match_key_value */
void test_OS_DBSearch_address_match_value_ip_value_match(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "10.10.10.10", &data->node), 1);
}

void test_OS_DBSearch_address_match_value_ip_value_mismatch(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "172.16.0.1", &data->node), 0);
}

void test_OS_DBSearch_address_match_value_subnet_value_match(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "192.168.1.25", &data->node), 1);
}

void test_OS_DBSearch_address_match_value_subnet_value_mismatch(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "10.20.30.40", &data->node), 0);
}

void test_OS_DBSearch_address_match_value_not_listed(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "8.8.8.8", &data->node), 0);
}

void test_OS_DBSearch_address_match_value_no_list(void **state) {
    address_value_state *data = *state;

    data->rule->db = NULL;

    assert_int_equal(OS_DBSearch(data->rule, "10.10.10.10", &data->node), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_cdblist
        cmocka_unit_test(test_os_remove_cdblist_OK),
        // Tests os_remove_cdbrules
        cmocka_unit_test(test_os_remove_cdbrules_OK),
        // Tests OS_FindList
        cmocka_unit_test(test_OS_FindList_dont_match),
        cmocka_unit_test(test_OS_FindList_empty_node),
        cmocka_unit_test(test_OS_FindList_cdb_match),
        cmocka_unit_test(test_OS_FindList_txt_match),
        // Tests OS_ListLoadRules
        cmocka_unit_test(test_OS_ListLoadRules_rule_null_check),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked_and_load),
        cmocka_unit_test(test_OS_ListLoadRules_already_load),
        // Tests OS_DBSearch with address_match_key_value
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_ip_value_match, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_ip_value_mismatch, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_subnet_value_match, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_subnet_value_mismatch, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_not_listed, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_no_list, setup_address_match_value, teardown_address_match_value),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
