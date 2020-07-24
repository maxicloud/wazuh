/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest.h"


void *w_logtest_init() {

    w_logtest_connection connection;

    if (w_logtest_init_parameters() == OS_INVALID) {
        merror(LOGTEST_ERROR_INV_CONF);
        return NULL;
    }

    if (!w_logtest_conf.enabled) {
        minfo(LOGTEST_DISABLED);
        return NULL;
    }

    if (connection.sock = OS_BindUnixDomain(LOGTEST_SOCK, SOCK_STREAM, OS_MAXSTR), connection.sock < 0) {
        merror(LOGTEST_ERROR_BIND_SOCK, LOGTEST_SOCK, errno, strerror(errno));
        return NULL;
    }

    if (w_logtest_sessions = OSHash_Create(), !w_logtest_sessions) {
        merror(LOGTEST_ERROR_INIT_HASH);
        return NULL;
    }

    w_mutex_init(&connection.mutex, NULL);

    minfo(LOGTEST_INITIALIZED);

    for (int i = 1; i < w_logtest_conf.threads; i++) {
        w_create_thread(w_logtest_main, &connection);
    }

    w_logtest_main(&connection);

    close(connection.sock);
    if (unlink(LOGTEST_SOCK)) {
        merror(DELETE_ERROR, LOGTEST_SOCK, errno, strerror(errno));
    }

    w_mutex_destroy(&connection.mutex);

    return NULL;
}


int w_logtest_init_parameters() {

    int modules = CLOGTEST;

    w_logtest_conf.enabled = true;
    w_logtest_conf.threads = LOGTEST_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_SESSION_TIMEOUT;

    if (ReadConfig(modules, OSSECCONF, NULL, NULL) < 0) {
        return OS_INVALID;
    }

    return OS_SUCCESS;
}


void *w_logtest_main(w_logtest_connection *connection) {

    int client;
    char msg_received[OS_MAXSTR];
    int size_msg_received;

    while(1) {

        w_mutex_lock(&connection->mutex);

        if (client = accept(connection->sock, (struct sockaddr *)NULL, NULL), client < 0) {
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(errno));
            continue;
        }

        w_mutex_unlock(&connection->mutex);

        if (size_msg_received = recv(client, msg_received, OS_MAXSTR, 0), size_msg_received < 0) {
            merror(LOGTEST_ERROR_RECV_MSG, strerror(errno));
            close(client);
            continue;
        }

        close(client);
    }

    return NULL;
}


void w_logtest_process_log(int token) {

}



w_logtest_session_t *w_logtest_initialize_session(int token, char **msg_error) {

    w_logtest_session_t *session;

    session->token = token;
    session->last_connection = 0;

    /* Create list to save previous events */
    os_calloc(1, sizeof(EventList), session->eventlist);
    OS_CreateEventList(Config.memorysize, session->eventlist);

    /* Load decoders */
    session->decoderlist_forpname = NULL;
    session->decoderlist_nopname = NULL;

    char **decodersfiles = Config.decoders;

    while (decodersfiles && *decodersfiles) {
        if (!ReadDecodeXML(*decodersfiles, &session->decoderlist_forpname, &session->decoderlist_nopname)) {
            return NULL;
        }

        os_free(*decodersfiles);
        decodersfiles++;
    }

    /* Load CDB list */
    session->cdblistnode = NULL;
    session->cdblistrule = NULL;

    char **listfiles = Config.lists;

    while (listfiles && *listfiles) {
        if (Lists_OP_LoadList(*listfiles, &session->cdblistnode) < 0) {
            return NULL;
        }
        os_free(*listfiles);
        listfiles++;
    }

    Lists_OP_MakeAll(0, 0, &session->cdblistnode);

    /* Load rules */
    session->rule_list = NULL;

    char **rulesfiles = Config.includes;

    while (rulesfiles && *rulesfiles) {
        if (Rules_OP_ReadRules(*rulesfiles, &session->rule_list, &session->cdblistnode) < 0) {
            return NULL;
        }

        os_free(*rulesfiles);
        rulesfiles++;
    }

    /* Associate rules and CDB lists */
    OS_ListLoadRules(&session->cdblistnode, &session->cdblistrule);

    /* _setlevels */


    /* Creating rule hash */
    if (session->g_rules_hash = OSHash_Create(), !session->g_rules_hash) {
        return NULL;
    }

    AddHash_Rule(session->rule_list);

    /* Initiate the FTS list */
    session->fts_list = NULL;


    /* Initialize the Accumulator */



    return session;
}

/*

typedef struct w_logtest_session_t {

    int token;                              ///< Client ID
    time_t last_connection;                 ///< Timestamp of the last query

    RuleNode *rule_list;                    ///< Rule list
    OSDecoderNode *decoderlist_forpname;    ///< Decoder list to match logs which have a program name
    OSDecoderNode *decoderlist_nopname;     ///< Decoder list to match logs which haven't a program name
    ListNode *cdblistnode;                  ///< List of CDB lists
    ListRule *cdblistrule;                  ///< List to attach rules and CDB lists
    EventList *eventlist;                   ///< Previous events list
    OSHash *g_rules_hash;                   ///< Hash table of rules
    OSList *fts_list;                       ///< Save FTS previous events
    OSHash *fts_store;                      ///< Save FTS values processed
    OSHash *acm_store;                      ///< Hash to save data which have the same id
    int acm_lookups;                        ///< Counter of the number of times purged. Option accumulate
    time_t acm_purge_ts;                    ///< Counter of the time interval of last purge. Option accumulate

} w_logtest_session_t;
*/

void w_logtest_remove_session(w_logtest_session_t *session) {

    /* Remove rule list and rule hash */

    OSHash_Free(session->g_rules_hash);

    /* Remove decoder list */


    /* Remove cdblistnode and cdblistrule */


    /* Remove list of previous events */


    /* Remove fts list and hash */

    OSHash_Free(session->fts_store);

    /* Remove accumulator hash */

    OSHash_Free(session->acm_lookups);
}


void w_logtest_check_active_sessions() {

}
