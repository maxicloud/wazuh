/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "syscheckd/syscheck.h"

extern int set_winsacl(const char *dir, int position);
extern int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable);

extern PSID everyone_sid;
extern size_t ev_sid_size;
/**************************************************************************/
/*************************WRAPS - GROUP SETUP******************************/
int test_group_setup(void **state) {
    int ret;
    ret = Read_Syscheck_Config("test_syscheck.conf");
    return ret;
}


void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}
/**************************************************************************/
/***************************set_winsacl************************************/
void test_set_winsacl_failed_opening(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);
    expect_string(__wrap__merror, formatted_msg, "(6648): OpenProcessToken() failed. Error '500'.");

    set_winsacl(syscheck.dir[0], 0);
}

void test_set_winsacl_failed_privileges(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0); // Fail lookup privilege

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);
    expect_string(__wrap__merror, formatted_msg,  "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 500");

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 501);
    expect_string(__wrap__merror, formatted_msg,  "(6659): The privilege could not be activated. Error: '501'.");

    will_return(wrap_win_whodata_CloseHandle, 0);
    set_winsacl(syscheck.dir[0], 0);
}

void test_set_winsacl_failed_security_descriptor(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    // Increase privileges
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, -1);
    expect_string(__wrap__merror, formatted_msg, "(6650): GetNamedSecurityInfo() failed. Error '-1'");

    // Reduce Privilege
    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");

    will_return(wrap_win_whodata_CloseHandle, 0);

    set_winsacl(syscheck.dir[0], 0);
}
/**************************************************************************/

void test_set_privilege_lookup_error (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 1);
}

void test_set_privilege_adjust_token_error (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6634): AdjustTokenPrivileges() failed. Error: '5'");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 1);
}

void test_set_privilege_elevate_privilege (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 1);

    assert_int_equal(ret, 0);
}

void test_set_privilege_reduce_privilege (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 0);
}

void test_w_update_sacl_AllocateAndInitializeSid_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6683): Could not obtain the sid of Everyone. Error '5'.");

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_OpenProcessToken_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) NULL);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6684): OpenProcessToken() failed. Error '5'.");

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_add_privilege_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    }

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6685): The privilege could not be activated. Error: '5'.");

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_GetNamedSecurityInfo_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_FILE_NOT_FOUND);

    expect_string(__wrap__merror, formatted_msg, "(6686): GetNamedSecurityInfo() failed. Error '2'");

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_GetAclInformation_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 0);

    expect_string(__wrap__merror, formatted_msg, "(6687): The size of the 'C:\\a\\path' SACL could not be obtained.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_alloc_new_sacl_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, NULL);

    expect_string(__wrap__merror, formatted_msg, "(6688): No memory could be reserved for the new SACL of 'C:\\a\\path'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_InitializeAcl_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6689): The new SACL for 'C:\\a\\path' could not be created. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_alloc_ace_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, NULL);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6690): No memory could be reserved for the new ACE of 'C:\\a\\path'. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_CopySid_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;
    SYSTEM_AUDIT_ACE ace;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6691): Could not copy the everyone SID for 'C:\\a\\path'. Error: '1-5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_old_sacl_GetAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, NULL);
    will_return(wrap_win_whodata_GetAce, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6692): The ACE number 0 for 'C:\\a\\path' could not be obtained.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_old_sacl_AddAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6693): The ACE number 0 of 'C:\\a\\path' could not be copied to the new ACL.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_new_sacl_AddAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6694): The new ACE could not be added to 'C:\\a\\path'. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_SetNamedSecurityInfo_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_PATH_NOT_FOUND);

    expect_string(__wrap__merror, formatted_msg,
        "(6695): SetNamedSecurityInfo() failed. Error: '3'");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_remove_privilege_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    }

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6685): The privilege could not be activated. Error: '5'.");

    /* Retry set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_w_update_sacl_success(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, 0);
}

/**************************************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {
        /* set_winsacl */
        cmocka_unit_test(test_set_winsacl_failed_opening),
        cmocka_unit_test(test_set_winsacl_failed_privileges),
        cmocka_unit_test(test_set_winsacl_failed_security_descriptor),
        /* set_privilege */
        cmocka_unit_test(test_set_privilege_lookup_error),
        cmocka_unit_test(test_set_privilege_adjust_token_error),
        cmocka_unit_test(test_set_privilege_elevate_privilege),
        cmocka_unit_test(test_set_privilege_reduce_privilege),

        cmocka_unit_test(test_w_update_sacl_AllocateAndInitializeSid_error),
        cmocka_unit_test(test_w_update_sacl_OpenProcessToken_error),
        cmocka_unit_test(test_w_update_sacl_add_privilege_error),
        cmocka_unit_test(test_w_update_sacl_GetNamedSecurityInfo_error),
        cmocka_unit_test(test_w_update_sacl_GetAclInformation_error),
        cmocka_unit_test(test_w_update_sacl_alloc_new_sacl_error),
        cmocka_unit_test(test_w_update_sacl_InitializeAcl_error),
        cmocka_unit_test(test_w_update_sacl_alloc_ace_error),
        cmocka_unit_test(test_w_update_sacl_CopySid_error),
        cmocka_unit_test(test_w_update_sacl_old_sacl_GetAce_error),
        cmocka_unit_test(test_w_update_sacl_old_sacl_AddAce_error),
        cmocka_unit_test(test_w_update_sacl_new_sacl_AddAce_error),
        cmocka_unit_test(test_w_update_sacl_SetNamedSecurityInfo_error),
        cmocka_unit_test(test_w_update_sacl_remove_privilege_error),
        cmocka_unit_test(test_w_update_sacl_success),
    };

    return cmocka_run_group_tests(tests, test_group_setup, NULL);
}