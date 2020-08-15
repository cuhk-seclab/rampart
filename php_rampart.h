/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2014-2016 Qafoo GmbH
 *  Copyright (c) 2016 Tideways GmbH
 *  Copyright (c) 2018 Chinese University of Hong Kong Wei Meng
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifndef PHP_RAMPART_H
#define PHP_RAMPART_H

extern zend_module_entry rampart_module_entry;
#define phpext_rampart_ptr &rampart_module_entry

#define PHP_RAMPART_VERSION "1.0.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#    define PHP_RAMPART_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#    define PHP_RAMPART_API __attribute__ ((visibility("default")))
#else
#    define PHP_RAMPART_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/* Function call stat database */
#define DATABASE "/var/log/rampart/db/stat.db"
#define BUFFER_SIZE 256

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names.  */
#define ROOT_SYMBOL                "main()"

/* Size of most recent system stat array */
#define SYSTEM_STAT_SIZE 3

/* Timer interval to check system stat */
#define INTERVAL 250 /* 250 milliseconds */

/* Hierarchical profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define TIDEWAYS_FLAGS_NO_BUILTINS   0x0001 /* do not profile builtins */
#define TIDEWAYS_FLAGS_CPU           0x0002 /* gather CPU times for funcs */
#define TIDEWAYS_FLAGS_MEMORY        0x0004 /* gather memory usage for funcs */
#define TIDEWAYS_FLAGS_NO_USERLAND   0x0008 /* do not profile userland functions */
#define TIDEWAYS_FLAGS_NO_COMPILE    0x0010 /* do not profile require/include/eval */
#define TIDEWAYS_FLAGS_NO_HIERACHICAL 0x0040

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif

#if PHP_VERSION_ID < 70000
struct _zend_string {
    char *val;
    int   len;
    int   persistent;
};
typedef struct _zend_string zend_string;
typedef long zend_long;
typedef int strsize_t;
typedef zend_uint uint32_t;
#endif

typedef struct _xdebug_func {
    char *class;
    char *function;
    int   type;
    int   internal;
} xdebug_func;

/*
    Declare any global variables you may need between the BEGIN
    and END macros here:

ZEND_BEGIN_MODULE_GLOBALS(rampart)
    zend_long  global_value;
    char *global_string;
ZEND_END_MODULE_GLOBALS(rampart)
*/

/* Tideways maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
    uint64                  tsc_start;         /* start value for wall clock timer */
    uint64                  cpu_start;         /* start value for CPU clock timer */
    long int                mu_start_hprof;                    /* memory usage */
    long int                pmu_start_hprof;              /* peak memory usage */
    struct hp_entry_t      *prev_hprof;        /* ptr to prev entry being profiled */
    zend_ulong              hash_entry;        /* hash_code for the entry */
    //uint8                   hash_code; [> 8-bit hash_code for the function name  <]
    unsigned int            depth;             /* depth of the entry in the stack */
#if defined(REPORT_MODE) && REPORT_MODE > 1
    char                    filename[BUFFER_SIZE];
    int                     lineno;
#endif
} hp_entry_t;


/* This entry contains the profiling stats of an entry. If an hash_entry appears
 * multiple times in one request, the stats are accumulated into one entry. */
typedef struct prof_entry_t {
    zend_ulong              hash_entry;     /* hash_code for the entry */
    long                    ct;             /* count of calls of the entry  */
    long                    wt;             /* wallclock time */
    long                    cpu;            /* real CPU clock time */
    long                    mu;             /* memory usage */
    long                    pmu;            /* peak memory usage */
} prof_entry_t;


/* Tideways's global state.
 *
 * This structure is instantiated once.  Initialize defaults for attributes in
 * hp_init_profiler_state() Cleanup/free attributes in
 * hp_clean_profiler_state() */
ZEND_BEGIN_MODULE_GLOBALS(hp)

    /*       ----------   Global attributes:  -----------       */

    /* Indicates if Tideways is currently enabled */
    int              enabled;

    /* Indicates if Tideways was ever enabled during this request */
    int              ever_enabled;

    int              prepend_overwritten;

    /* Holds all the Tideways statistics */
#if PHP_VERSION_ID >= 70000
    zval            stats_count;
    zval            exception;
#else
    zval            *stats_count;
    zval            *exception;
#endif
    uint64          start_time;

    /* Top of the profile stack */
    hp_entry_t      *entries;

    /* freelist of hp_entry_t chunks for reuse... */
    hp_entry_t      *entry_free_list;

    char            *root;
    zend_ulong      root_hash_entry;

    double timebase_factor;

    /* system stats */
    uint64 prev_cpu[4]; /* last cpu measurments in /proc/stat */
    uint64 current_cpu[4]; /* current cpu measurments in /proc/stat */
    double cpu_usages[SYSTEM_STAT_SIZE]; /* past SYSTEM_STAT_SIZE cpu usages */
    uint32 stat_num; /* number of stat measurments so far */

    int num_entries; /* number of entries in the stack */
    FILE *log_f;
    char php_file_name[256];
    char log_file_name[256];
    char v_user_id[46]; /* a virtual user id for distinguishing users; can use remote addr, cookies, etc. */
    char uri_key[512];
    int test_rule;
    int prof_timer;
    int pid;
    int random_num;
    int record_end_stat;
    int check_history_count; /* A positive value indicating that the times check_history() had returned positive value */

    /* Tideways flags */
    uint32 tideways_flags;

    int compile_count;
    double compile_wt;
    uint64 cpu_start;

    int stack_threshold;
ZEND_END_MODULE_GLOBALS(hp)

#ifdef ZTS
#define TWG(v) TSRMG(hp_globals_id, zend_hp_globals *, v)
#else
#define TWG(v) (hp_globals.v)
#endif

PHP_MINIT_FUNCTION(tideways);
PHP_MSHUTDOWN_FUNCTION(tideways);
PHP_RINIT_FUNCTION(tideways);
PHP_RSHUTDOWN_FUNCTION(tideways);
PHP_MINFO_FUNCTION(tideways);
PHP_GINIT_FUNCTION(hp);
PHP_GSHUTDOWN_FUNCTION(hp);


/* Always refer to the globals in your function as RAMPART_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/
#define RAMPART_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(rampart, v)

#if defined(ZTS) && defined(COMPILE_DL_RAMPART)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif /* PHP_RAMPART_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
