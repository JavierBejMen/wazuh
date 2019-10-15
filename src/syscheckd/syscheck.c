/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */

#include "shared.h"
#include "syscheck.h"
#include "rootcheck/rootcheck.h"

// Global variables
syscheck_config syscheck;
pthread_cond_t audit_thread_started;
pthread_cond_t audit_hc_started;
pthread_cond_t audit_db_consistency;
int sys_debug_level;

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;


void init_magic(magic_t *cookie_ptr)
{
    if (!cookie_ptr || *cookie_ptr) {
        return;
    }

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if (!*cookie_ptr) {
        const char *err = magic_error(*cookie_ptr);
        merror(FIM_ERROR_LIBMAGIC_START, err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        merror(FIM_ERROR_LIBMAGIC_LOAD, err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif /* USE_MAGIC */

/* Read syscheck internal options */
static void read_internal(int debug_level)
{
    syscheck.tsleep = (unsigned int) getDefine_Int("syscheck", "sleep", 0, 64);
    syscheck.sleep_after = getDefine_Int("syscheck", "sleep_after", 1, 9999);
    syscheck.rt_delay = getDefine_Int("syscheck", "rt_delay", 1, 1000);
    syscheck.max_depth = getDefine_Int("syscheck", "default_max_depth", 1, 320);
    syscheck.file_max_size = (size_t)getDefine_Int("syscheck", "file_max_size", 0, 4095) * 1024 * 1024;

#ifndef WIN32
    syscheck.max_audit_entries = getDefine_Int("syscheck", "max_audit_entries", 1, 4096);
#endif
    sys_debug_level = getDefine_Int("syscheck", "debug", 0, 2);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        int debug_level = sys_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    return;
}

// Initialize syscheck data
int fim_initialize() {
    // Create store data
    syscheck.fim_entry = rbtree_init();

    if (!syscheck.fim_entry) {
        merror_exit(FIM_CRITICAL_DATA_CREATE, "rb-tree init");
    }

#ifndef WIN32
    // Create hash table for inodes entries
    syscheck.fim_inode = OSHash_Create();

    if (!syscheck.fim_inode) {
        merror_exit(FIM_CRITICAL_DATA_CREATE, "inode hash table");
    }

    if (!OSHash_setSize(syscheck.fim_inode, OS_SIZE_4096)) {
        merror(LIST_ERROR);
        return (0);
    }
#endif

    rbtree_set_dispose(syscheck.fim_entry, (void (*)(void *))free_entry_data);
    w_mutex_init(&syscheck.fim_entry_mutex, NULL);

    return 0;
}


#ifdef WIN32
/* syscheck main for Windows */
int Start_win32_Syscheck()
{
    int debug_level = 0;
    int r = 0;
    char *cfg = DEFAULTCPATH;
    /* Read internal options */
    read_internal(debug_level);

    mdebug1(STARTED_MSG);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        /* Disabled */
        if (!syscheck.dir) {
            minfo(FIM_DIRECTORY_NOPROVIDED);
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL, 0, NULL, -1);
        } else if (!syscheck.dir[0]) {
            minfo(FIM_DIRECTORY_NOPROVIDED);
        }

        syscheck.dir[0] = NULL;

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            syscheck.ignore[0] = NULL;
        }

        if (!syscheck.registry) {
            dump_syscheck_entry(&syscheck, "", 0, 1, NULL, 0, NULL, -1);
        }
        syscheck.registry[0].entry = NULL;

        minfo(FIM_DISABLED);
    }

    /* Rootcheck config */
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    if (!syscheck.disabled) {
#ifndef WIN_WHODATA
        int whodata_notification = 0;
        /* Remove whodata attributes */
        for (r = 0; syscheck.dir[r]; r++) {
            if (syscheck.opts[r] & WHODATA_ACTIVE) {
                if (!whodata_notification) {
                    whodata_notification = 1;
                    minfo(FIM_REALTIME_INCOMPATIBLE);
                }
                syscheck.opts[r] &= ~WHODATA_ACTIVE;
                syscheck.opts[r] |= REALTIME_ACTIVE;
            }
        }
#endif

        /* Print options */
        r = 0;
        // TODO: allow sha256 sum on registries
        while (syscheck.registry[r].entry != NULL) {
            minfo(FIM_MONITORING_REGISTRY, syscheck.registry[r].entry, syscheck.registry[r].arch == ARCH_64BIT ? " [x64]" : "");
            r++;
        }

        /* Print directories to be monitored */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            char optstr[ 1024 ];
            minfo(FIM_MONITORING_DIRECTORY, syscheck.dir[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
            if (syscheck.tag && syscheck.tag[r] != NULL) {
                mdebug1(FIM_TAG_ADDED, syscheck.tag[r], syscheck.dir[r]);
            }
            r++;
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

        /* Print sregex ignores. */
        if(syscheck.ignore_regex)
            for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

        /* Print registry ignores. */
        if(syscheck.registry_ignore)
            for (r = 0; syscheck.registry_ignore[r].entry != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "registry", syscheck.registry_ignore[r].entry);

        /* Print sregex registry ignores. */
        if(syscheck.registry_ignore_regex)
            for (r = 0; syscheck.registry_ignore_regex[r].regex != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "registry", syscheck.registry_ignore_regex[r].regex->raw);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo(FIM_NO_DIFF, syscheck.nodiff[r]);
                r++;
            }
        }

        /* Start up message */
        minfo(STARTUP_MSG, getpid());
    }

    /* Some sync time */
    sleep(syscheck.tsleep * 5);
    fim_initialize();

    /* Wait if agent started properly */
    os_wait();

    start_daemon();

    return 0;
}
#endif /* WIN32 */

#ifndef WIN32

/* Print help statement */
__attribute__((noreturn)) static void help_syscheckd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out(" ");
    exit(1);
}

/* Syscheck unix main */
int main(int argc, char **argv)
{
    int c, r;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    const char *cfg = DEFAULTCPATH;
    gid_t gid;
    const char *group = GROUPGLOBAL;
#ifdef ENABLE_AUDIT
    audit_thread_active = 0;
    whodata_alerts = 0;
#endif

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vtdhfc:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_syscheckd();
                break;
            case 'd':
                nowDebug();
                debug_level ++;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_syscheckd();
                break;
        }
    }

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Read internal options */
    read_internal(debug_level);

    mdebug1(STARTED_MSG);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        if (!syscheck.dir) {
            if (!test_config) {
                minfo(FIM_DIRECTORY_NOPROVIDED);
            }
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL, 0, NULL, -1);
        } else if (!syscheck.dir[0]) {
            if (!test_config) {
                minfo(FIM_DIRECTORY_NOPROVIDED);
            }
        }

        syscheck.dir[0] = NULL;

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            syscheck.ignore[0] = NULL;
        }

        if (!test_config) {
            minfo(FIM_DISABLED);
        }
    }

    /* Rootcheck config */
    if (rootcheck_init(test_config) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    /* Exit if testing config */
    if (test_config) {
        exit(0);
    }

    /* Setup libmagic */
#ifdef USE_MAGIC
    init_magic(&magic_cookie);
#endif

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    } else {
        if (chdir(DEFAULTDIR) == -1) {
            merror_exit(CHDIR_ERROR, DEFAULTDIR, errno, strerror(errno));
        }
    }

    /* Start signal handling */
    StartSIG(ARGV0);

    // Start com request thread
    w_create_thread(syscom_main, NULL);

    /* Create pid */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    if (syscheck.rootcheck) {
        rootcheck_connect();
    }

    /* Connect to the queue */
    if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        minfo(FIM_WAITING_QUEUE, DEFAULTQPATH, errno, strerror(errno), 5);

        sleep(5);
        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            /* more 10 seconds of wait */
            minfo(FIM_WAITING_QUEUE, DEFAULTQPATH, errno, strerror(errno), 10);
            sleep(10);
            if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQPATH);
            }
        }
    }

    if (!syscheck.disabled) {

        /* Start up message */
        minfo(STARTUP_MSG, (int)getpid());

        /* Print directories to be monitored */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            char optstr[ 1024 ];

            if (!syscheck.converted_links[r]) {
                minfo(FIM_MONITORING_DIRECTORY, syscheck.dir[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
            } else {
                minfo(FIM_MONITORING_LDIRECTORY, syscheck.dir[r], syscheck.converted_links[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
            }

            if (syscheck.tag && syscheck.tag[r] != NULL)
                mdebug1(FIM_TAG_ADDED, syscheck.tag[r], syscheck.dir[r]);
            r++;
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

        /* Print sregex ignores. */
        if(syscheck.ignore_regex)
            for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo(FIM_NO_DIFF, syscheck.nodiff[r]);
                r++;
            }
        }

        /* Check directories set for real time */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            if (syscheck.opts[r] & REALTIME_ACTIVE) {
#if defined (INOTIFY_ENABLED) || defined (WIN32)
                struct stat file_stat;
                if (w_stat(syscheck.dir[r], &file_stat) >= 0) {
                    switch(file_stat.st_mode & S_IFMT) {
                    case FIM_REGULAR:
                        mwarn(FIM_WARN_FILE_REALTIME, syscheck.dir[r]);
                        break;

                    case FIM_DIRECTORY:
                        minfo(FIM_REALTIME_MONITORING_DIRECTORY, syscheck.dir[r]);
                        break;
                    }
                } else {
                    mdebug2(FIM_STAT_FAILED, syscheck.dir[r], errno, strerror(errno));
                }
#else
                mwarn(FIM_WARN_REALTIME_DISABLED, syscheck.dir[r]);
#endif
            }
            r++;
        }
    }

    /* Some sync time */
    sleep(syscheck.tsleep * 5);
    fim_initialize();

    // Audit events thread
    if (syscheck.enable_whodata) {
#ifdef ENABLE_AUDIT
        int out = audit_init();
        if (out < 0)
            mwarn(FIM_WARN_AUDIT_THREAD_NOSTARTED);
#else
        merror(FIM_ERROR_WHODATA_AUDIT_SUPPORT);
#endif
    }

    /* Start the daemon */
    start_daemon();

    // We shouldn't reach this point unless syscheck is disabled
    while(1) {
        pause();
    }

}

#endif /* !WIN32 */
