/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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


#include "../syscheckd/syscheck.h"

/* redefinitons/wrapping */

int __wrap_OS_ConnectUnixDomain()
{
    return mock();
}

int __wrap_IsDir(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsLink(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsFile(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsSocket(const char * sock)
{
    check_expected(sock);
    return mock();
}

int __wrap_audit_restart()
{
    return mock();
}

int __wrap__minfo()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap_fopen(const char *filename, const char *mode)
{
    check_expected(filename);
    return mock();
}

size_t __real_fwrite(const void * ptr, size_t size, size_t count, FILE * stream);
size_t __wrap_fwrite(const void * ptr, size_t size, size_t count, FILE * stream)
{
    FILE * str = 0;
    if ((void*)stream > (void*)ptr) {
        return __real_fwrite(ptr, size, count, stream);
    }
    return 1;
}

int __wrap_fprintf()
{
    return 1;
}

int __wrap_fclose()
{
    return 0;
}

int __wrap_unlink()
{
    return 1;
}

int __wrap_symlink(const char *path1, const char *path2)
{
    check_expected(path1);
    check_expected(path2);
    return mock();
}

int __wrap_audit_open()
{
    return 1;
}

int __wrap_audit_close()
{
    return 1;
}

int __wrap_audit_get_rule_list()
{
    return mock();
}

int __wrap_W_Vector_length()
{
    return mock();
}

int __wrap_search_audit_rule()
{
    return mock();
}

int __wrap_audit_add_rule()
{
    return mock();
}

int __wrap_W_Vector_insert_unique()
{
    return mock();
}

int __wrap_SendMSG()
{
    return 1;
}

int __wrap_fim_whodata_event(whodata_evt * w_evt)
{
    check_expected(w_evt->process_id);
    check_expected(w_evt->user_id);
    check_expected(w_evt->group_id);
    check_expected(w_evt->process_name);
    check_expected(w_evt->path);
    check_expected(w_evt->audit_uid);
    check_expected(w_evt->effective_uid);
    check_expected(w_evt->inode);
    check_expected(w_evt->ppid);
    return 1;
}

static int free_string(void **state)
{
    char * string = *state;
    free(string);
    return 0;
}

/* tests */


void test_check_auditd_enabled(void **state)
{
    (void) state;
    int ret;

    ret = check_auditd_enabled();
    assert_return_code(ret, 0);
}


void test_init_auditd_socket_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, 124);
    ret = init_auditd_socket();
    assert_int_equal(ret, 124);
}


void test_init_auditd_socket_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, -5);
    ret = init_auditd_socket();
    assert_int_equal(ret, -1);
}


void test_set_auditd_config_audit3_plugin_created(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit3_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 0);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 0);
}


void test_set_auditd_config_audit2_plugin_created(void **state)
{
    (void) state;

    // Not Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 1);
    // Audit 2
    expect_string(__wrap_IsDir, file, "/etc/audisp/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit2_socket = "/etc/audisp/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit2_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit2_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 0);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 0);
}


void test_set_auditd_config_audit_socket_not_created(void **state)
{
    (void) state;

    syscheck.restart_audit = 1;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit3_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 1);

    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 1);

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;
    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 0);

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;
    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


void test_audit_get_id(void **state)
{
    (void) state;

    const char* event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 res=1";

    char *ret;
    ret = audit_get_id(event);
    *state = ret;

    assert_string_equal(ret, "1571145421.379:659");
}


void test_init_regex(void **state)
{
    (void) state;
    int ret;

    ret = init_regex();

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_not_added(void **state)
{
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, 1);
    will_return(__wrap_W_Vector_insert_unique, 1);

    int ret;
    ret = add_audit_rules_syscheck();

    assert_int_equal(ret, 1);
}


void test_add_audit_rules_syscheck_added(void **state)
{
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc(2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc(2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already added
    will_return(__wrap_search_audit_rule, 1);

    // Add rule
    will_return(__wrap_W_Vector_insert_unique, 1);

    int ret;
    ret = add_audit_rules_syscheck();

    free(syscheck.dir[0]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 1);
}


void test_filterkey_audit_events_custom(void **state)
{
    (void) state;

    char *key = "test_key";
    syscheck.audit_key = calloc(2, sizeof(char *));
    syscheck.audit_key[0] = calloc(strlen(key) + 2, sizeof(char));
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=test_key";
    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 2);
}


void test_filterkey_audit_events_discard(void **state)
{
    (void) state;

    char *key = "test_key";
    syscheck.audit_key = calloc(2, sizeof(char *));
    syscheck.audit_key[0] = calloc(strlen(key) + 2, sizeof(char));
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"test_invalid_key\"";
    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 0);
}


void test_filterkey_audit_events_hc(void **state)
{
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_hc\"";
    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 3);
}


void test_filterkey_audit_events_fim(void **state)
{
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_fim\"";
    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 1);
}


void test_gen_audit_path(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path2(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "./test/";
    char * path1 = "./test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path3(void **state)
{
    (void) state;

    char * cwd = "/";
    char * path0 = "root/test/";
    char * path1 = "root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path4(void **state)
{
    (void) state;

    char * cwd = "/";
    char * path0 = "/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path5(void **state)
{
    (void) state;

    char * cwd = "/root/test";
    char * path0 = "../test/";
    char * path1 = "../test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path6(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "./file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/root/file");
}


void test_gen_audit_path7(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "../file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_audit_parse(void **state)
{
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\" \
        type=PATH msg=audit(1571914029.306:3004254): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571914029.306:3004254): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_value(__wrap_fim_whodata_event, w_evt->audit_uid, 0);
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse_hex(void **state)
{
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571923546.947:3004294): arch=c000003e syscall=316 success=yes exit=0 a0=ffffff9c a1=7ffe425fc770 a2=ffffff9c a3=7ffe425fc778 items=4 ppid=3212 pid=51452 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=66696C655FC3B1 key=\"wazuh_fim\" \
        type=CWD msg=audit(1571923546.947:3004294): cwd=2F726F6F742F746573742F74657374C3B1 \
        type=PATH msg=audit(1571923546.947:3004294): item=0 name=2F726F6F742F746573742F74657374C3B1 inode=19 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=1 name=2E2E2F74657374C3B1322F inode=30 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=2 name=66696C655FC3B1 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=3 name=2E2E2F74657374C3B1322F66696C655FC3B163 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571923546.947:3004294): proctitle=6D760066696C655FC3B1002E2E2F74657374C3B1322F66696C655FC3B163 \
    ";

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ2/file_ñc");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    audit_parse(buffer);
}


void test_audit_parse_delete(void **state)
{
    (void) state;

    char * buffer = "type=CONFIG_CHANGE msg=audit(1571920603.069:3004276): auid=0 ses=5 op=remove_rule key=\"wazuh_fim\" list=4 res=1";

    // In audit_reload_rules()
    will_return(__wrap_audit_get_rule_list, 5);
    will_return(__wrap_W_Vector_length, 3);
    will_return(__wrap_search_audit_rule, 1);
    will_return(__wrap_W_Vector_insert_unique, 1);

    audit_parse(buffer);
}


void test_audit_parse_mv(void **state)
{
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571925844.299:3004308): arch=c000003e syscall=82 success=yes exit=0 a0=7ffdbb76377e a1=556c16f6c2e0 a2=0 a3=100 items=5 ppid=3210 pid=52277 auid=20 uid=30 gid=40 euid=50 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571925844.299:3004308): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=\"folder/test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=\"folder/test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571925844.299:3004308): proctitle=6D76002E2F7465737400666F6C646572 \
    ";

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 52277);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "40");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/mv");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "20");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "50");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3210);

    audit_parse(buffer);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_auditd_enabled),
        cmocka_unit_test(test_init_auditd_socket_success),
        cmocka_unit_test(test_init_auditd_socket_failure),
        cmocka_unit_test(test_set_auditd_config_audit2_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit3_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit_socket_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error),
        cmocka_unit_test_teardown(test_audit_get_id, free_string),
        cmocka_unit_test(test_init_regex),
        cmocka_unit_test(test_add_audit_rules_syscheck_added),
        cmocka_unit_test(test_add_audit_rules_syscheck_not_added),
        cmocka_unit_test(test_filterkey_audit_events_custom),
        cmocka_unit_test(test_filterkey_audit_events_discard),
        cmocka_unit_test(test_filterkey_audit_events_fim),
        cmocka_unit_test(test_filterkey_audit_events_hc),
        cmocka_unit_test_teardown(test_gen_audit_path, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path2, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path3, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path4, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path5, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path6, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path7, free_string),
        cmocka_unit_test(test_audit_parse),
        cmocka_unit_test(test_audit_parse_hex),
        cmocka_unit_test(test_audit_parse_delete),
        cmocka_unit_test(test_audit_parse_mv),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
