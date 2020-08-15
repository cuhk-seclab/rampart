/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2014-2016 Qafoo GmbH
 *  Copyright (c) 2016 Tideways GmbH
 *  Copyright (c) 2018 The Chinese University of Hong Kong
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_rampart.h"
#include "rampart_setting.h"

#include "zend_exceptions.h"
#include "main/SAPI.h"

#include <sys/time.h> /* for settimer */
#include <signal.h> /* for signal */

#include <sqlite3.h> /* for sqlite3 */
#include <stdlib.h> /* for rand() */
#include <string.h>
#include <assert.h>

#if PHP_VERSION_ID < 70000
#define hp_ptr_dtor(val) zval_ptr_dtor( &val )
#define TWG_ARRVAL(val) Z_ARRVAL_P(val)

#else
#define hp_ptr_dtor(val) zval_ptr_dtor(val)
#define TWG_ARRVAL(val) Z_ARRVAL(val)

typedef size_t strsize_t;
/* removed/uneeded macros */
#define TSRMLS_CC
#endif

#define VERBOSE_ERROR 1
#define VERBOSE_WARNING 2
#define VERBOSE_DEBUG 3
#define VERBOSE_INFO 4

/* Flag to log the filename and line number of a function call */
#define LOG_FN_LN 0

#define VERBOSE 0
#define PRINT_BR 0
#define WRITE_LOG 0

/* Report additional information when handling abnormal requests. Effective only when WRITE_LOG > 0 */
#define REPORT_MODE 0

/* Threshold for determining timeout in micro seconds */
#define TIMEOUT_MAX 15000000
#define TIMEOUT_MIN 100000


/**
 * A hash function to calculate a 64-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 * @param len, size_t, size of str.
 * @param hash, zend_ulong, optoinal hash seed.
 *
 */

static zend_always_inline zend_ulong inline_hash_func(const char *str, size_t len, zend_ulong h)
{
    register zend_ulong hash = h;
    if (hash == 0)
#if PHP_VERSION_ID >= 70000
        hash = Z_UL(5381);
#else
        hash = 5381;
#endif

    /* variant with the hash unrolled eight times */
    for (; len >= 8; len -= 8) {
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
        hash = ((hash << 5) + hash) + *str++;
    }
    switch (len) {
        case 7: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 6: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 5: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 4: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 3: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 2: hash = ((hash << 5) + hash) + *str++; /* fallthrough... */
        case 1: hash = ((hash << 5) + hash) + *str++; break;
        case 0: break;
EMPTY_SWITCH_DEFAULT_CASE()
    }

    /* Hash value can't be zero, so we always set the high bit */
#if PHP_VERSION_ID >= 70000
#if SIZEOF_ZEND_LONG == 8
    return hash | Z_UL(0x8000000000000000);
#elif SIZEOF_ZEND_LONG == 4
    return hash | Z_UL(0x80000000);
#else
# error "Unknown SIZEOF_ZEND_LONG"
#endif
#else // PHP_VERSION_ID >= 70000
#if INTPTR_MAX == INT64_MAX
    return hash | 0x8000000000000000;
#elif INTPTR_MAX == INT32_MAX
    return hash | 0x80000000;
#else
# error "Unknown pointer size or missing size macros!"
#endif
#endif
}


static zend_always_inline zval* zend_compat_hash_find_const(HashTable *ht, const char *key, strsize_t len)
{
#if PHP_VERSION_ID < 70000
    zval **tmp, *result;
    if (zend_hash_find(ht, key, len+1, (void**)&tmp) == SUCCESS) {
        result = *tmp;
        return result;
    }
    return NULL;
#else
    return zend_hash_str_find(ht, key, len);
#endif
}

static zend_always_inline zval* zend_compat_hash_index_find(HashTable *ht, zend_ulong idx)
{
#if PHP_VERSION_ID < 70000
    zval **tmp, *result;

    if (zend_hash_index_find(ht, idx, (void **) &tmp) == FAILURE) {
        return NULL;
    }

    result = *tmp;
    return result;
#else
    return zend_hash_index_find(ht, idx);
#endif
}


#if PHP_VERSION_ID >= 70000
static void (*_zend_execute_ex) (zend_execute_data *execute_data);
static void (*_zend_execute_internal) (zend_execute_data *execute_data, zval *return_value);
#elif PHP_VERSION_ID < 50500
static void (*_zend_execute) (zend_op_array *ops TSRMLS_DC);
static void (*_zend_execute_internal) (zend_execute_data *data, int ret TSRMLS_DC);
#else
static void (*_zend_execute_ex) (zend_execute_data *execute_data TSRMLS_DC);
static void (*_zend_execute_internal) (zend_execute_data *data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);
#endif

#if PHP_MAJOR_VERSION == 7
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data);
#elif PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute (zend_op_array *ops TSRMLS_DC);
#else
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data TSRMLS_DC);
#endif
#if PHP_MAJOR_VERSION == 7
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *return_value);
#elif PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, int ret TSRMLS_DC);
#else
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);
#endif

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index)  (index >> 3)
#define INDEX_2_BIT(index)   (1 << (index & 0x7));

/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */

static void hp_begin(long tideways_flags TSRMLS_DC);
static void hp_stop(TSRMLS_D);
static void hp_end(TSRMLS_D);
static void record_rule(int type);
static void dump_stats_count(TSRMLS_D);

static uint64 cycle_timer();
static uint64 cpu_timer();

static void hp_free_the_free_list(TSRMLS_D);
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D);
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC);
static double get_timebase_factor();
static long get_us_interval(struct timeval *start, struct timeval *end);
static inline double get_us_from_tsc(uint64 count TSRMLS_DC);

static char** str_split(char* a_str, const char a_delim);
static int set_user_id();

static int check_history();
static int query_rule(time_t t);
static void check_test(double avg_cpu);
static void process_rule(int query_result);

static void timeout_handler(int signum);
static int reset_timer(int which, int new_which, unsigned new_interval, void (*func)(int));

static int find_line_number_for_current_execute_point(zend_execute_data *edata TSRMLS_DC);

/* If you declare any globals in php_rampart.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(rampart)
*/
ZEND_DECLARE_MODULE_GLOBALS(hp)

/* True global resources - no need for thread safety here */

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("rampart.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_rampart_globals, rampart_globals)
    STD_PHP_INI_ENTRY("rampart.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_rampart_globals, rampart_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_rampart_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_rampart_compiled)
{
    char *arg = NULL;
    size_t arg_len, len;

#if PHP_VERSION_ID < 70000
    char *strg;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &arg, &arg_len) == FAILURE) {
        return;
    }
    len = spprintf(&strg, 0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "rampart", arg);
    RETURN_STRINGL(strg, len, 0);
#else
    zend_string *strg;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &arg, &arg_len) == FAILURE) {
        return;
    }
    strg = strpprintf(0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "rampart", arg);
    RETURN_STR(strg);
#endif
}
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_rampart_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_rampart_init_globals(zend_rampart_globals *rampart_globals)
{
    rampart_globals->global_value = 0;
    rampart_globals->global_string = NULL;
}
*/
/* }}} */

PHP_GINIT_FUNCTION(hp)
{
    hp_globals->enabled = 0;
    hp_globals->ever_enabled = 0;
    hp_globals->tideways_flags = 0;
#if PHP_VERSION_ID < 70000
    hp_globals->stats_count = NULL;
    hp_globals->exception = NULL;
#else
    ZVAL_UNDEF(&hp_globals->stats_count);
    ZVAL_UNDEF(&hp_globals->exception);
#endif
    hp_globals->entries = NULL;
    hp_globals->root = NULL;
    hp_globals->stack_threshold = 50000;
}

PHP_GSHUTDOWN_FUNCTION(hp)
{
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(rampart)
{
    /* If you have INI entries, uncomment these lines
    REGISTER_INI_ENTRIES();
    */
    int i;
    /*REGISTER_INI_ENTRIES();*/

    /* Get the number of available logical CPUs. */
    TWG(timebase_factor) = get_timebase_factor();

#if PHP_VERSION_ID < 70000
    TWG(stats_count) = NULL;
#endif

    /* no free hp_entry_t structures to start with */
    TWG(entry_free_list) = NULL;

#if PHP_VERSION_ID < 50500
    _zend_execute = zend_execute;
    zend_execute  = hp_execute;
#else
    _zend_execute_ex = zend_execute_ex;
    zend_execute_ex  = hp_execute_ex;
#endif

    _zend_execute_internal = zend_execute_internal;
    zend_execute_internal = hp_execute_internal;

#if defined(DEBUG)
    /* To make it random number generator repeatable to ease testing. */
    srand(0);
#else
    srand(time(NULL));
#endif

    memset(TWG(prev_cpu), 0, sizeof(uint64) * 4);
    memset(TWG(current_cpu), 0, sizeof(uint64) * 4);
    memset(TWG(cpu_usages), 0, sizeof(double) * SYSTEM_STAT_SIZE);
    TWG(stat_num) = 0;
    TWG(num_entries) = 0;

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(rampart)
{
    /* uncomment this line if you have INI entries
    UNREGISTER_INI_ENTRIES();
    */
    /* free any remaining items in the free list */
    hp_free_the_free_list(TSRMLS_C);

    /* Remove proxies, restore the originals */
#if PHP_VERSION_ID < 50500
    zend_execute = _zend_execute;
#else
    zend_execute_ex = _zend_execute_ex;
#endif

    zend_execute_internal = _zend_execute_internal;

    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(rampart)
{
#if defined(COMPILE_DL_RAMPART) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    zend_long tideways_flags = TIDEWAYS_FLAGS_CPU | TIDEWAYS_FLAGS_NO_BUILTINS;

    if (TWG(enabled)) {
        hp_stop(TSRMLS_C);
    }

#if defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
    php_printf("<br>");
#endif
    php_printf("Beginning of a request\n");
#endif

    memset(TWG(php_file_name), '\0', sizeof(TWG(php_file_name)));
    memset(TWG(v_user_id), '\0', sizeof(TWG(v_user_id)));
    memset(TWG(uri_key), '\0', sizeof(TWG(uri_key)));
    TWG(test_rule) = 0;
    TWG(pid) = getpid();
    TWG(random_num) = rand();
    TWG(record_end_stat) = TWG(random_num) % PROF_RATIO;
    TWG(check_history_count) = 0;
    TWG(prof_timer) = 0;
#if defined(WRITE_LOG) && WRITE_LOG > 0
    time_t t = time(NULL);
    memset(TWG(log_file_name), '\0', sizeof(TWG(log_file_name)));
    sprintf(TWG(log_file_name), "/var/log/rampart/logs/%d-%d-%d.log", t, TWG(pid), TWG(random_num));
    TWG(log_f) = fopen(TWG(log_file_name), "w");
#else
    TWG(log_f) = NULL;
#endif

    hp_begin(tideways_flags TSRMLS_CC);

    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(rampart)
{
    hp_end(TSRMLS_C);

#if defined(WRITE_LOG) && WRITE_LOG > 0
    fclose(TWG(log_f));
#endif
    TWG(log_f) = NULL;

#if defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
    php_printf("<br>");
#endif
    php_printf("End of a request\n");
#endif
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(rampart)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "rampart support", "enabled");
    php_info_print_table_end();

    /* Remove comments if you have entries in php.ini
    DISPLAY_INI_ENTRIES();
    */
}
/* }}} */

/* {{{ rampart_functions[]
 *
 * Every user visible function must have an entry in rampart_functions[].
 */
const zend_function_entry rampart_functions[] = {
    PHP_FE(confirm_rampart_compiled,   NULL)       /* For testing, remove later. */
    PHP_FE_END  /* Must be the last line in rampart_functions[] */
};
/* }}} */

/* {{{ rampart_module_entry
 */
zend_module_entry rampart_module_entry = {
    STANDARD_MODULE_HEADER,
    "rampart",
    rampart_functions,
    PHP_MINIT(rampart),
    PHP_MSHUTDOWN(rampart),
    PHP_RINIT(rampart),        /* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(rampart),    /* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(rampart),
    PHP_RAMPART_VERSION,
    PHP_MODULE_GLOBALS(hp), /* globals descriptor */
    PHP_GINIT(hp),          /* globals ctor */
    PHP_GSHUTDOWN(hp),      /* globals dtor */
    NULL,                   /* post deactivate */
    STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_RAMPART
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(rampart)
#endif

/**
 * Read the profiling records from the sqlite3 database.
 * Return a positive number to be used as the new timer in timeout_handler().
 *
 * @author wei
 */
static int check_history()
{
    sqlite3 *db = 0;
    sqlite3_stmt *stmt;
    char * sErrMsg = 0;
    int rc = -1;
    char sSQL[BUFFER_SIZE] = "\0";
    int retVal = 0;

    /*rc = sqlite3_open(":memory:", &db);*/
    rc = sqlite3_open(DATABASE, &db);
    if (rc) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Cannot open database: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
        fprintf(TWG(log_f), "Cannot open database: %s\n", sqlite3_errmsg(db));
#endif
    } else {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Opened database successfully, support multithread: %d\n", sqlite3_threadsafe());
#if defined(WRITE_LOG) && WRITE_LOG > 0
        fprintf(TWG(log_f), "Opened database successfully, support multithread: %d\n", sqlite3_threadsafe());
#endif
#endif
        /*sqlite3_exec(db, "PRAGMA busy_timeout = 50", NULL, NULL, &sErrMsg);*/

        sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &sErrMsg);
        sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &sErrMsg);
        /*sqlite3_exec(db, "PRAGMA journal_mode = WAL", NULL, NULL, &sErrMsg);*/
        sqlite3_exec(db, "PRAGMA cache_size = 100000", NULL, NULL, &sErrMsg);

        sprintf(sSQL, "SELECT ct, cpu, cpu_variance FROM PERF_RECORDS WHERE hash=?1 LIMIT 1");
        rc = sqlite3_prepare_v2(db, sSQL, BUFFER_SIZE, &stmt, 0);
        if (rc != SQLITE_OK) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("Error preparing stmt: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
            fprintf(TWG(log_f), "Error preparing stmt: %s\n", sqlite3_errmsg(db));
#endif
            sqlite3_close(db);
            return retVal;
        }

        hp_entry_t *current = TWG(entries);
        int num_queries = 0;
        long current_cpu_count = cpu_timer();
        long current_cpu = 0;
        while (current != NULL) {
            if (current->depth <= MAX_PROF_DEPTH) {
                zend_ulong hash_entry = current->hash_entry;
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
                php_printf("<br>");
#endif
                php_printf("Checking history of hash=%u\n", hash_entry);
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
                fprintf(TWG(log_f), "Checking history of hash=%u, %ld, depth=%d\n", hash_entry, hash_entry, current->depth);
#endif
                sqlite3_bind_int64(stmt, 1, hash_entry);
                num_queries++;
                double var = 0;
                zend_ulong hash;
                long ct = 0;
                long cpu = 0;

                current_cpu = get_us_from_tsc(current_cpu_count - current->cpu_start TSRMLS_CC);
                rc = sqlite3_step(stmt);
                if (rc == SQLITE_ROW) {
                    ct = (long)sqlite3_column_int64(stmt, 0);
                    cpu = (long)sqlite3_column_int64(stmt, 1);
                    var = sqlite3_column_double(stmt, 2);
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
                    php_printf("<br>");
#endif
                    php_printf("hash=%u, depth=%d, ct=%ld, cpu=%ld, var=%f, current_cpu=%ld\n", hash_entry, current->depth, ct, cpu, var, current_cpu);
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
                    fprintf(TWG(log_f), "hash=%u, depth=%d, ct=%ld, cpu=%ld, var=%f, current_cpu=%ld\n", hash_entry, current->depth, ct, cpu, var, current_cpu);
#endif
                    /* XXX We require at least 5 measurments */
                    if (ct >= 5) {
                        double avg_cpu = (double)cpu / (double)ct;
                        if (var == 0) {
                            double ratio = 0.16;
                            var = ratio * avg_cpu * avg_cpu;
                        }
                        double stddev = sqrt(var);
                        double threshold = avg_cpu + 10 * stddev;
                        if (threshold < TIMEOUT_MIN)
                            threshold = TIMEOUT_MIN;
                        else if (threshold > TIMEOUT_MAX)
                            threshold = TIMEOUT_MAX;
                        if (current_cpu > threshold) {
#if (defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING) || (defined(WRITE_LOG) && WRITE_LOG > 0)
                            time_t t = time(NULL);
                            struct tm tm = *localtime(&t);
                            char current_time[20];
                            memset(current_time, '\0', sizeof(current_time));
                            sprintf(current_time, "%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
                            if (strlen(TWG(php_file_name)) > 0) {
                                fprintf(TWG(log_f), "%s\tEnd profiling [%s-%d], v_user_id=%s\n", current_time, TWG(php_file_name), TWG(pid), TWG(v_user_id));
                            }
#endif
#endif // (defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING) || (defined(WRITE_LOG) && WRITE_LOG > 0)
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
                            php_printf("<br>");
#endif
                            php_printf("%s\tCPU: %ld > AVG (%.2f) + 10 * stddev (%.2f).\n", current_time, current_cpu, avg_cpu, stddev);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
                            fprintf(TWG(log_f), "%s\tCPU: %ld > AVG (%.2f) + 10 * stddev (%.2f).\n", current_time, current_cpu, avg_cpu, stddev);
#endif
                            retVal = stddev;
                            if (retVal < TIMEOUT_MIN/10)
                                retVal = TIMEOUT_MIN/10;
                            else if (retVal > TIMEOUT_MAX)
                                retVal = TIMEOUT_MAX;
                            retVal = retVal / 1000;
                            break;
                        } // if (current_cpu > threshold)
                        else {
                            unsigned new_interval = threshold - current_cpu;
                            if (new_interval > TIMEOUT_MIN) {
                                new_interval = new_interval / 1000;
#if defined(WRITE_LOG) && WRITE_LOG > 0
#if defined(REPORT_MODE) && REPORT_MODE > 0
                                time_t t = time(NULL);
                                struct tm tm = *localtime(&t);
                                char current_time[20];
                                memset(current_time, '\0', sizeof(current_time));
                                sprintf(current_time, "%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                                if (strlen(TWG(php_file_name)) > 0) {
                                    fprintf(TWG(log_f), "%s\tProfiling [%s-%d], v_user_id=%s\n", current_time, TWG(php_file_name), TWG(pid), TWG(v_user_id));
                                }
                                fprintf(TWG(log_f), "hash=%u, depth=%d, ct=%ld, cpu=%ld, var=%f, current_cpu=%ld\n", hash_entry, current->depth, ct, cpu, var, current_cpu);
#endif
                                fprintf(TWG(log_f), "Resetting REAL timer to PROF timer, threshold=%lf, new_interval=%u\n", threshold, new_interval);
#endif
                                if (reset_timer(ITIMER_REAL, ITIMER_PROF, new_interval, (void (*)(int))timeout_handler) < 0) {
                                /*if (reset_timer(ITIMER_REAL, ITIMER_VIRTUAL, new_interval, (void (*)(int))timeout_handler) < 0) {*/
                                /*if (reset_timer(ITIMER_REAL, ITIMER_REAL, new_interval, (void (*)(int))timeout_handler) < 0) {*/
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
                                    php_printf("<br>");
#endif
                                    php_printf("Error resetting timer\n");
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
                                    fprintf(TWG(log_f), "Error resetting timer\n");
#endif
                                }
                                else {
                                    TWG(prof_timer) = 1;
                                }
                                break;
                            } // if (new_interval > TIMEOUT_MIN)
                        } // else
                    } // if (ct > 5)
                }
                else if (rc == SQLITE_DONE) {
#if defined(WRITE_LOG) && WRITE_LOG > 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
                    fprintf(TWG(log_f), "Finished reading row\n");
#endif
                    break;
                }
                else {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
                    php_printf("<br>");
#endif
                    php_printf("Error in reading row: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
                    fprintf(TWG(log_f), "Error in reading row: %s\n", sqlite3_errmsg(db));
#endif
                    sqlite3_finalize(stmt);
                    break;
                }
                sqlite3_reset(stmt);
            } // if (current->depth <= MAX_PROF_DEPTH) {
            else {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
                php_printf("<br>");
#endif
                php_printf("Warning: Depth of entry-'%s' [%d] is greater than MAX_PROF_DEPTH!!!", current->depth);
#endif
            }
            if (retVal > 0)
                break;
            current = current->prev_hprof;
        } // while (current != NULL)
        sqlite3_clear_bindings(stmt);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    return retVal;
}


/**
 * Query the DB for any rule for handling the current request.
 * Return:
 *   0 if no rule is found or some error occurred;
 *   1 if a rule is active for blocking the matched requests;
 *   -1 if the rule has entered the 2nd lifespan and no request is being tested/explored;
 *   2 if a matched request is being tested;
 *   -2 if both lifespans of the rule have expired.
 *
 * @author wei
 */
static int query_rule(time_t t)
{
    if (!SG(request_info).request_uri)
        return 0;
    sqlite3 *db = 0;
    sqlite3_stmt *stmt;
    char * sErrMsg = 0;
    int rc = -1;
    char sSQL[BUFFER_SIZE] = "\0";
    int retVal = 0;

    /*rc = sqlite3_open(":memory:", &db);*/
    rc = sqlite3_open(DATABASE, &db);
    if (rc) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Cannot open database: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
        fprintf(TWG(log_f), "Cannot open database: %s\n", sqlite3_errmsg(db));
#endif
    } else {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Opened database successfully, support multithread: %d\n", sqlite3_threadsafe());
#if defined(WRITE_LOG) && WRITE_LOG > 0
        fprintf(TWG(log_f), "Opened database successfully, support multithread: %d\n", sqlite3_threadsafe());
#endif
#endif
        /*sqlite3_exec(db, "PRAGMA busy_timeout = 50", NULL, NULL, &sErrMsg);*/
        /*sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &sErrMsg);*/
        /*sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &sErrMsg);*/
        /*sqlite3_exec(db, "PRAGMA journal_mode = WAL", NULL, NULL, &sErrMsg);*/
        /*sqlite3_exec(db, "PRAGMA cache_size = 100000", NULL, NULL, &sErrMsg);*/

        sprintf(sSQL, "SELECT expiry, status FROM RULES WHERE uid=?1 AND uri_key=?2 LIMIT 1");
        rc = sqlite3_prepare_v2(db, sSQL, BUFFER_SIZE, &stmt, 0);
        if (rc != SQLITE_OK) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("Error preparing stmt: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
            fprintf(TWG(log_f), "Error preparing stmt: %s\n", sqlite3_errmsg(db));
#endif
            sqlite3_close(db);
            return retVal;
        }

#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Query rule of [%s-%s]\n", TWG(v_user_id), TWG(uri_key));
#if defined(WRITE_LOG) && WRITE_LOG > 0
        fprintf(TWG(log_f), "Query rule of [%s-%s]\n", TWG(v_user_id), TWG(uri_key));
#endif
#endif
        sqlite3_bind_text(stmt, 1, TWG(v_user_id), -1, NULL);
        sqlite3_bind_text(stmt, 2, TWG(uri_key), -1, NULL);

        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            double expiry_time = sqlite3_column_double(stmt, 0);
            int status = sqlite3_column_int64(stmt, 1);
            int expired = 0;
            if ((int)t < expiry_time) {
                retVal = 1; // ACTIVE
            }
            else {
                if (status > 0) {
                    retVal = -1; // TEST
                }
                else if (status == 0) {
                    retVal = 2; // TESTING
                }
                else {
                    retVal = -2; // REVOKED, INACTIVE
                    expired = 1;
                }
            }
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("retVal=%d, expired=%d, status=%d\n", retVal, expired, status);
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
            fprintf(TWG(log_f), "retVal=%d, expired=%d, status=%d\n", retVal, expired, status);
#endif
        }
        else if (rc == SQLITE_DONE) {
#if defined(WRITE_LOG) && WRITE_LOG > 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
            fprintf(TWG(log_f), "Finished reading row\n");
#endif
        }
        else {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("Error in reading row: %s\n", sqlite3_errmsg(db));
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
            fprintf(TWG(log_f), "Error in reading row: %s\n", sqlite3_errmsg(db));
#endif
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    return retVal;
}


/**
 * Probabilistically test a request or renew a rule.
 *
 * @author wei
 */
static void check_test(double avg_cpu)
{
    TWG(test_rule) = 2;
    time_t t = time(NULL);
    double threshold = (double)(CPU_USAGE_UPPER_THRESHOLD - avg_cpu * ALPHA) * 2.0 / (CPU_USAGE_UPPER_THRESHOLD + CPU_USAGE_LOWER_THRESHOLD);
    double score = (rand() % 100) / 100.0;
    if (score < threshold) {
        record_rule(1); /* TEST */
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("%d\tTesting Request!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
        fprintf(TWG(log_f), "%d\tTesting Request!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
    }
    else {
        record_rule(-2); /* RENEW */
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("%d\tRenewing Rule!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
        fprintf(TWG(log_f), "%d\tRenewing Rule!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
#if !(defined(TRAINING) && TRAINING > 0)
        if (TWG(log_f)) {
            fclose(TWG(log_f));
            TWG(log_f) = NULL;
        }
        exit(1);
#endif // !(defined(TRAINING) && TRAINING > 0)
    }
}

/**
 * Drop a request based on the rule query result
 *
 * @author wei
 */
static void process_rule(int query_result)
{
    if (query_result > 0) {
        time_t t = time(NULL);
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("%d\tDropping Request!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
        fprintf(TWG(log_f), "%d\tDropping Request!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
#if !(defined(TRAINING) && TRAINING > 0)
        if (TWG(log_f)) {
            fclose(TWG(log_f));
            TWG(log_f) = NULL;
        }
        exit(1);
#endif // !(defined(TRAINING) && TRAINING > 0)
    }
    else if (query_result == -1) {
        TWG(test_rule) = 1;
    }
}


/**
 * Split string by a_delim
 *
 * https://stackoverflow.com/questions/9210528/split-string-with-delimiters-in-c
 */
static char** str_split(char* a_str, const char a_delim) {
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

/**
 * Set $_SERVER["REMOTE_ADDR"] as v_user_id,
 * and generate uri_key based on request_uri and query string parameters.
 *
 * @author wei
 */
static int set_user_id()
{
    int s = 0;
    int l = 0;
    if (SG(request_info).query_string) {
        l = strlen(SG(request_info).request_uri);
        if (s+l < 256) {
            strcpy(TWG(uri_key)+s, SG(request_info).request_uri);
            s += l;
        }
        l = 1;
        if (s+l < 256) {
            *(TWG(uri_key)+s) = '-';
            s += l;
        }
    }
    if (SG(request_info).request_method) {
        l = strlen(SG(request_info).request_method);
        if (s+l < 256) {
            strcpy(TWG(uri_key)+s, SG(request_info).request_method);
            s += l;
        }
        l = 1;
        if (s+l < 256) {
            *(TWG(uri_key)+s) = '-';
            s += l;
        }
    }
    if (SG(request_info).query_string) {
        char **queries = str_split(SG(request_info).query_string, '&');
        int i;
        for (i = 0; *(queries + i); i++) {
            char **split = str_split(*(queries+i), '=');
            if (split) {
                char *key = *(split + 0);
                char *value = *(split + 1);
                l = strlen(key);
                if (s+l < 256) {
                    strcpy(TWG(uri_key)+s, key);
                    s += l;
                }
                l = 1;
                if (s+l < 256) {
                    *(TWG(uri_key)+s) = '&';
                    s += l;
                }
                int j;
                for (j = 0; *(split + j); j++) {
                    free(*(split + j));
                }
            }
            free(*(queries + i));
        }
        free(queries);
    }
#if PHP_VERSION_ID < 70000
    char *r_str;
    zval **arr;
    zval **remote_addr;
    if (zend_hash_find(&EG(symbol_table), "_SERVER", 8, (void**)&arr) == FAILURE)
        return -1;
    HashTable *server = Z_ARRVAL_PP(arr);
    if (zend_hash_find(server,"REMOTE_ADDR", 12, (void**)&remote_addr) != FAILURE && Z_TYPE_PP(remote_addr) == IS_STRING) {
        r_str = Z_STRVAL_PP(remote_addr);
        strcpy(TWG(v_user_id), r_str);
    }
#else
    char *r_str;
    zval *remote_addr;
    zend_string *server = zend_string_init("_SERVER", sizeof("_SERVER")-1, 0);
    zend_is_auto_global(server);
    HashTable *SERVER = Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]);
    if (SERVER == NULL)
        return -1;
    remote_addr = zend_hash_str_find(SERVER,"REMOTE_ADDR", sizeof("REMOTE_ADDR")-1);
    if (remote_addr != NULL && Z_TYPE_P(remote_addr) == IS_STRING) {
        r_str = Z_STRVAL_P(remote_addr);
        strcpy(TWG(v_user_id), r_str);
    }
#endif
    return 0;
}

/**
 * The timeout handler to check whole system resource usage
 *
 * @author wei
 */
static void timeout_handler(int signum)
{
    /* This number might not be reset in a new request as the same process might be used for processing multiple requests */
    static uint32_t count = 0;
    count++;
    time_t t = time(NULL);
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
    php_printf("<br>");
#endif
    php_printf("%d\tTimer expired %d times\n", t, count);
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
    fprintf(TWG(log_f), "%d\tTimer expired %d times\n", t, count);
#endif

    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_CPU) {
        FILE *fp = fopen("/proc/stat", "r");
        fscanf(fp, "%*s %llu %llu %llu %llu", &(TWG(current_cpu)[0]), &(TWG(current_cpu)[1]), &(TWG(current_cpu)[2]), &(TWG(current_cpu)[3]));
        fclose(fp);
        double avg = 0;
        if (count > 0) {
            uint64 n = (TWG(current_cpu)[0] + TWG(current_cpu)[1] + TWG(current_cpu)[2]) - (TWG(prev_cpu)[0] + TWG(prev_cpu)[1] + TWG(prev_cpu)[2]);
            double u = 100.0 * n / (n + TWG(current_cpu)[3] - TWG(prev_cpu)[3]);
            TWG(cpu_usages)[TWG(stat_num) % SYSTEM_STAT_SIZE] = u;
            double sum = 0;
            int i = TWG(stat_num) - SYSTEM_STAT_SIZE + 1;
            if (i < 0)
                i = 0;
            int num = TWG(stat_num) - i + 1;
            for (; i <= TWG(stat_num); i++) {
                sum += TWG(cpu_usages)[i % SYSTEM_STAT_SIZE];
            }
            avg = sum / num;
#if defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("CPU: current=%f, average[%d]=%f\n", u, num, avg);
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
            fprintf(TWG(log_f), "CPU: current=%f, average[%d]=%f\n", u, num, avg);
#endif
            TWG(stat_num)++;
        }
        memcpy(&TWG(prev_cpu), &TWG(current_cpu), sizeof(uint64) * 4);

#if defined(ENABLE_RULE) && ENABLE_RULE > 0
        if (TWG(test_rule) == 1) {
            check_test(avg);
        }
#endif
        int shouldTerminate = 0;
        int new_interval = 0;
        /* Only call check_history() once */
        if (TWG(check_history_count) == 0) {
            new_interval = check_history();
            if (new_interval > 0)
                TWG(check_history_count)++; /* We increase its value to indicate that the current request is a Positive */
        }
        if (TWG(check_history_count) > 0) {
            if (avg > CPU_USAGE_UPPER_THRESHOLD) {
                /* We only terminate a Positive request if the avg load is higher than the upper threshold */
                double threshold;
                double score;
                int shouldSleep = 0;
                threshold = (double)(TWG(check_history_count) * OMEGA + avg * ALPHA) / 100.0;
                /*if (avg > CPU_USAGE_LOWER_THRESHOLD)*/
                    /*threshold = (double)(TWG(check_history_count) * OMEGA + avg - CPU_USAGE_LOWER_THRESHOLD) / 100.0;*/
                /*else*/
                    /*threshold = 0;*/
                score = (rand() % 100) / 100.0;
#if defined(FORCE_TERMINATION) && FORCE_TERMINATION > 0
                score = 0; // Force termination
#endif
                if (score < threshold)
                    shouldTerminate = 1;
                else
                    shouldSleep = 1;
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
                fprintf(TWG(log_f), "Should Terminate=%d!!! check_history_count=%d, avg_cpu_usage=%f, threshold=%f, score=%f\n", shouldTerminate, TWG(check_history_count), avg, threshold, score);
#endif
                if (shouldSleep && SLEEP_TIME > 0) {
                    struct timespec ts;
                    ts.tv_sec = SLEEP_TIME / 1000;
                    ts.tv_nsec = (SLEEP_TIME % 1000) * 1000000;
                    nanosleep(&ts, NULL);
                }
            }
            if (TWG(check_history_count) == 1 && shouldTerminate == 0) {
                /* Reset the timer to expire in new_interval ms as a CPU timer to recalculate the score in case the request is not terminated immediately after the first check */
                int old_timer = ITIMER_REAL;
                if (TWG(prof_timer) > 0)
                    old_timer = ITIMER_PROF;
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
                if (TWG(prof_timer) > 0)
                    /*fprintf(TWG(log_f), "Resetting PROF timer to REAL timer, new_interval=%u\n", new_interval);*/
                    fprintf(TWG(log_f), "Resetting PROF timer to PROF timer, new_interval=%u\n", new_interval);
                else
                    /*fprintf(TWG(log_f), "Resetting REAL timer to REAL timer, new_interval=%u\n", new_interval);*/
                    fprintf(TWG(log_f), "Resetting REAL timer to PROF timer, new_interval=%u\n", new_interval);
                TWG(prof_timer) = 0;
#endif
                /*if (reset_timer(ITIMER_REAL, ITIMER_PROF, new_interval, (void (*)(int))timeout_handler) < 0) {*/
                /*if (reset_timer(old_timer, ITIMER_REAL, new_interval, (void (*)(int))timeout_handler) < 0) {*/
                if (reset_timer(old_timer, ITIMER_PROF, new_interval, (void (*)(int))timeout_handler) < 0) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
                    php_printf("<br>");
#endif
                    php_printf("Error resetting timer\n");
#endif
#if defined(WRITE_LOG) && WRITE_LOG > 0
                    fprintf(TWG(log_f), "Error resetting timer\n");
#endif
                }
            }
            if (shouldTerminate == 0)
                TWG(check_history_count)++; /* We increase its value to indicate that the current request is a Positive */
        }
        if (shouldTerminate) {
            time_t t = time(NULL);
#if defined(ENABLE_RULE) && ENABLE_RULE > 0
            record_rule(-1); /* KILL */
#endif
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("%d\tTerminating Process!!! v_user_id=%s, uri=%s, check_history_count=%d, avp_cpu_usage=%f\n", t, TWG(v_user_id), SG(request_info).request_uri, TWG(check_history_count), avg);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0)
            fprintf(TWG(log_f), "%d\tTerminating Process!!! v_user_id=%s, uri=%s, check_history_count=%d, avp_cpu_usage=%f\n", t, TWG(v_user_id), SG(request_info).request_uri, TWG(check_history_count), avg);
#if defined(REPORT_MODE) && REPORT_MODE > 1
            hp_entry_t *current = TWG(entries);
            while (current != NULL) {
                if (current->depth <= MAX_PROF_DEPTH) {
                    fprintf(TWG(log_f), "[KILL]\t%d\t%s\t%d\t%u\n", current->depth, current->filename, current->lineno, current->hash_entry);
                } // if (current->depth <= MAX_PROF_DEPTH) {
                current = current->prev_hprof;
            } // while (current != NULL)
#endif
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0)
#if !(defined(TRAINING) && TRAINING > 0)
            if (TWG(log_f)) {
                fclose(TWG(log_f));
                TWG(log_f) = NULL;
            }
            exit(1);
#endif // !(defined(TRAINING) && TRAINING > 0)
        }
    }
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */


/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state(TSRMLS_D)
{
    if (!TWG(ever_enabled)) {
        TWG(ever_enabled) = 1;
        TWG(entries) = NULL;
    }

    TWG(stack_threshold) = INI_INT("tideways.stack_threshold");

#if PHP_VERSION_ID >= 70000
    hp_ptr_dtor(&TWG(stats_count));
    array_init(&TWG(stats_count));
#else
    if (TWG(stats_count)) {
        hp_ptr_dtor(TWG(stats_count));
    }

    _ALLOC_INIT_ZVAL(TWG(stats_count));
    array_init(TWG(stats_count));
#endif
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
void hp_clean_profiler_state(TSRMLS_D)
{
#if PHP_VERSION_ID >= 70000
    hp_ptr_dtor(&TWG(stats_count));
    ZVAL_NULL(&TWG(stats_count));
#else
    if (TWG(stats_count)) {
        hp_ptr_dtor(TWG(stats_count));
        TWG(stats_count) = NULL;
    }
#endif

    TWG(entries) = NULL;
    TWG(ever_enabled) = 0;
}

/*
 * Start profiling - called just before calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define BEGIN_PROFILING(entries, symbol, execute_data)                          \
    do {                                                                        \
        /* Use a hash code to filter most of the string comparisons. */         \
        hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry(TSRMLS_C);            \
        (cur_entry)->prev_hprof = (*(entries));                                 \
        hp_mode_hier_beginfn_cb((cur_entry), symbol, execute_data TSRMLS_CC);   \
        /* Update entries linked list */                                        \
        (*(entries)) = (cur_entry);                                             \
    } while (0)

/*
 * Stop profiling - called just after calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define END_PROFILING(entries, data)                                        \
    do {                                                                    \
        if (TWG(record_end_stat) == 0) {                                    \
            hp_mode_hier_endfn_cb((entries), data TSRMLS_CC);               \
        }                                                                   \
        hp_entry_t *cur_entry = (*entries);                                 \
        /* Free top entry and update entries linked list */                 \
        (*(entries)) = (*(entries))->prev_hprof;                            \
        hp_fast_free_hprof_entry(cur_entry TSRMLS_CC);                      \
    } while (0)


static char *hp_concat_char(const char *s1, size_t len1, const char *s2, size_t len2, const char *seperator, size_t sep_len)
{
    char *result = emalloc(len1+len2+sep_len+1);

    strcpy(result, s1);
    strcat(result, seperator);
    strcat(result, s2);
    result[len1+len2+sep_len] = '\0';

    return result;
}

/**
 * Get the name of the current function. The name is qualified with
 * the class name if the function is in a class.
 *
 * @author kannan, hzhao
 */
static char *hp_get_function_name(zend_execute_data *execute_data TSRMLS_DC)
{
    const char        *cls = NULL;
    char              *ret = NULL;
    zend_function      *curr_func;

    if (!execute_data) {
        return NULL;
    }

#if PHP_VERSION_ID < 70000
    const char        *func = NULL;
    curr_func = execute_data->function_state.function;
    func = curr_func->common.function_name;

    if (!func) {
        // This branch includes execution of eval and include/require(_once) calls
        // We assume it is not 1999 anymore and not much PHP code runs in the
        // body of a file and if it is, we are ok with adding it to the caller's wt.
        return NULL;
    }

    /* previously, the order of the tests in the "if" below was
     * flipped, leading to incorrect function names in profiler
     * reports. When a method in a super-type is invoked the
     * profiler should qualify the function name with the super-type
     * class name (not the class name based on the run-time type
     * of the object.
     */
    if (curr_func->common.scope) {
        cls = curr_func->common.scope->name;
    } else if (execute_data->object) {
        cls = Z_OBJCE(*execute_data->object)->name;
    }

    if (cls) {
        char* sep = "::";
        ret = hp_concat_char(cls, strlen(cls), func, strlen(func), sep, 2);
    } else {
        ret = estrdup(func);
    }
#else
    zend_string *func = NULL;
    curr_func = execute_data->func;
    func = curr_func->common.function_name;

    if (!func) {
        if (
            execute_data &&
            execute_data->prev_execute_data &&
            execute_data->prev_execute_data->func->type == ZEND_USER_FUNCTION &&
            execute_data->prev_execute_data->opline &&
            execute_data->prev_execute_data->opline->opcode == ZEND_INCLUDE_OR_EVAL
        ) {
            switch (execute_data->prev_execute_data->opline->extended_value) {
                case ZEND_EVAL:
                    ret = estrdup("{eval}");
                    break;
                case ZEND_INCLUDE:
                    ret = estrdup("{include}");
                    break;
                case ZEND_REQUIRE:
                    ret = estrdup("{require}");
                    break;
                case ZEND_INCLUDE_ONCE:
                    ret = estrdup("{include_once}");
                    break;
                case ZEND_REQUIRE_ONCE:
                    ret = estrdup("{require_once}");
                    break;
                default:
                    ret = estrdup("{unknown}");
                    break;
            }
        } else if (
        /*if (*/
            execute_data &&
            !execute_data->prev_execute_data
        ) {
            ret = estrdup("{main}");
        }
    } else if (curr_func->common.scope != NULL) {
        char* sep = "::";
        cls = curr_func->common.scope->name->val;
        ret = hp_concat_char(cls, curr_func->common.scope->name->len, func->val, func->len, sep, 2);
    } else {
        ret = emalloc(ZSTR_LEN(func)+1);
        strcpy(ret, ZSTR_VAL(func));
        ret[ZSTR_LEN(func)] = '\0';
    }
#endif

    return ret;
}

/**
 * Free any items in the free list.
 */
static void hp_free_the_free_list(TSRMLS_D)
{
    hp_entry_t *p = TWG(entry_free_list);
    hp_entry_t *cur;

    while (p) {
        cur = p;
        p = p->prev_hprof;
        free(cur);
    }
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D)
{
    hp_entry_t *p;

    p = TWG(entry_free_list);

    if (p) {
        TWG(entry_free_list) = p->prev_hprof;
        return p;
    } else {
        return (hp_entry_t *)malloc(sizeof(hp_entry_t));
    }
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 *
 * @author kannan
 */
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC)
{
    /* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
    p->prev_hprof = TWG(entry_free_list);
    TWG(entry_free_list) = p;
}

/**
 * Append the given stat with the given value
 * If the stat was not set before, inits the stat as a new array
 *
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  value    Value of the stat to be appended
 * @return void
 * @author wei
 */
void hp_add_value(zval *counts, char *name, long value TSRMLS_DC)
{
    HashTable *ht;
    zval *array, array_val;

    if (!counts) {
        return;
    }

    ht = HASH_OF(counts);

    if (!ht) {
        return;
    }

    array = zend_compat_hash_find_const(ht, name, strlen(name));

    if (!array) {
#if PHP_VERSION_ID >= 70000
        array = &array_val;
        array_init(array);
        zend_hash_str_update(ht, name, strlen(name), array);
#else
        MAKE_STD_ZVAL(array);
        array_init(array);
        zend_hash_update(ht, name, strlen(name)+1, &array, sizeof(zval*), NULL);
#endif
    }
    add_next_index_long(array, value);
}


/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get the current wallclock timer
 *
 * @return 64 bit unsigned integer
 * @author cjiang
 */
static uint64 cycle_timer() {
#ifdef __APPLE__
    return mach_absolute_time();
#else
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#endif
}

/**
 * Get the current real CPU clock timer
 */
static uint64 cpu_timer() {
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    struct timespec s;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#else
    struct rusage ru;

    getrusage(RUSAGE_SELF, &ru);

    return ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
        ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
#endif
}

/**
 * Get time delta in microseconds.
 */
static long get_us_interval(struct timeval *start, struct timeval *end)
{
    return (((end->tv_sec - start->tv_sec) * 1000000)
            + (end->tv_usec - start->tv_usec));
}

/**
 * Convert from TSC counter values to equivalent microseconds.
 *
 * @param uint64 count, TSC count value
 * @return 64 bit unsigned integer
 *
 * @author cjiang
 */
static inline double get_us_from_tsc(uint64 count TSRMLS_DC)
{
    return count / TWG(timebase_factor);
}

/**
 * Get the timebase factor necessary to divide by in cycle_timer()
 */
static double get_timebase_factor()
{
#ifdef __APPLE__
    mach_timebase_info_data_t sTimebaseInfo;
    (void) mach_timebase_info(&sTimebaseInfo);

    return (sTimebaseInfo.numer / sTimebaseInfo.denom) * 1000;
#else
    return 1.0;
#endif
}

/**
 * TIDEWAYS_MODE_HIERARCHICAL's begin function callback
 *
 * @author kannan
 */
void hp_mode_hier_beginfn_cb(hp_entry_t *current, char* fname, zend_execute_data *data TSRMLS_DC)
{
    zend_ulong prev_hash_entry = 0;
    hp_entry_t *prev = current->prev_hprof;
    if (prev) {
        prev_hash_entry = prev->hash_entry;
        if (prev_hash_entry == TWG(root_hash_entry)) {
            /* prev entry is TWG(root) */
#if PHP_VERSION_ID >= 70000
            char *file_name = ZSTR_VAL(data->func->op_array.filename);
#else
            const char *file_name = data->op_array->filename;
#endif
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("Filename=%s\n", file_name);
            fprintf(TWG(log_f), "Filename=%s\n", file_name);
#endif
            prev_hash_entry = inline_hash_func(file_name, strlen(file_name), prev_hash_entry);
            (prev)->hash_entry = prev_hash_entry;

            strcpy(TWG(php_file_name), file_name);

            set_user_id();
            time_t t = time(NULL);
#if defined(ENABLE_RULE) && ENABLE_RULE > 0
            int result = query_rule(t);
            process_rule(result);
#endif

#if defined(WRITE_LOG) && WRITE_LOG > 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_DEBUG
            char *pch;
            pch = strrchr(file_name, '/');

            if (pch) {
                struct tm tm = *localtime(&t);
                char current_time[20];
                memset(current_time, '\0', sizeof(current_time));
                sprintf(current_time, "%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                fprintf(TWG(log_f), "%s\tBegin profiling [%s-%d], v_user_id=%s\n", current_time, TWG(php_file_name), TWG(pid), TWG(v_user_id));
                if (TWG(record_end_stat) == 0) {
                    fprintf(TWG(log_f), "I am being profiled\n");
                }
            }
#endif
        }
        current->depth = prev->depth + 1;

#if (defined(WRITE_LOG) && WRITE_LOG > 0) && ((defined(LOG_FN_LN) && LOG_FN_LN > 0) || (defined(REPORT_MODE) && REPORT_MODE > 1))
        /*char *file_name = ZSTR_VAL(data->func->op_array.filename);*/
        char *file_name = estrdup(zend_get_executed_filename(TSRMLS_C));
        /* lineno is the first line in the definition body of the function being called */
        int lineno = find_line_number_for_current_execute_point(data TSRMLS_CC);
#if defined(REPORT_MODE) && REPORT_MODE > 1
        memset(current->filename, '\0', sizeof(current->filename));
        strcpy(current->filename, file_name);
        current->lineno = lineno;
#endif
#if (defined(LOG_FN_LN) && LOG_FN_LN > 0) && (defined(WRITE_LOG) && WRITE_LOG > 0)
        fprintf(TWG(log_f), "[FCALL]\t%d\t%s\t%d\t%s\n", current->depth, file_name, lineno, fname);
#endif
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0) && ((defined(LOG_FN_LN) && LOG_FN_LN > 0) || (defined(REPORT_MODE) && REPORT_MODE > 1))

    }
    else {
        current->depth = TWG(num_entries);
    }
    current->hash_entry = inline_hash_func(fname, strlen(fname), prev_hash_entry);

#if defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
    php_printf("<br>");
#endif
    php_printf("B-fcall '%s', hash='%u', depth=%d\n", fname, current->hash_entry, current->depth);
#endif

    /* Get CPU usage */
    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_CPU) {
        current->cpu_start = cpu_timer();
        /*current->cpu_start = clock();*/
    }

    /* Get memory usage */
    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_MEMORY) {
        current->mu_start_hprof  = zend_memory_usage(0 TSRMLS_CC);
        current->pmu_start_hprof = zend_memory_peak_usage(0 TSRMLS_CC);
    }

    /* Get start tsc counter */
    /*current->tsc_start = cycle_timer();*/
}

/**
 * **********************************
 * TIDEWAYS END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * TIDEWAYS_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
void hp_mode_hier_endfn_cb(hp_entry_t **entries, zend_execute_data *data TSRMLS_DC)
{
#if !(defined(TRAINING) && TRAINING > 0)
    if (TWG(check_history_count) > 0)
        return;
#endif
    hp_entry_t      *top = (*entries);
    zval            *stats, stat_val;
    long int         mu_end;
    long int         pmu_end;
    uint64   tsc_end;
    double   wt, cpu;

    /* Get end tsc counter */
    /*tsc_end = cycle_timer();*/
    /*wt = get_us_from_tsc(tsc_end - top->tsc_start TSRMLS_CC);*/

    if ((TWG(tideways_flags) & TIDEWAYS_FLAGS_NO_HIERACHICAL) > 0) {
        return;
    }

    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_CPU) {
        cpu = get_us_from_tsc(cpu_timer() - top->cpu_start TSRMLS_CC);
        /*cpu = clock() - top->cpu_start;*/
    }

    /* Get the stat array */

    /* store stats using hash_entry instead of symbol */
    stats = zend_compat_hash_index_find(TWG_ARRVAL(TWG(stats_count)), top->hash_entry);

    if (stats == NULL) {
#if PHP_VERSION_ID >= 70000
        stats = &stat_val;
        array_init(stats);
        zend_hash_index_update(TWG_ARRVAL(TWG(stats_count)), top->hash_entry, stats);
#else
        MAKE_STD_ZVAL(stats);
        array_init(stats);
        zend_hash_index_update(TWG_ARRVAL(TWG(stats_count)), top->hash_entry, &stats, sizeof(zval*), NULL);
#endif
    }

    /* Bump stats in the stats hashtable */
#if defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
    php_printf("<br>");
#endif
    php_printf("\nE-fcall, hash='%u', depth=%d, wt=%f,", top->hash_entry, top->depth, wt);
#endif

    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_CPU) {
        /* Bump CPU stats in the stats hashtable */
        hp_add_value(stats, "cpu", cpu TSRMLS_CC);
#if defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
        php_printf(" cpu=%f ", cpu);
#endif
    }

    if (TWG(tideways_flags) & TIDEWAYS_FLAGS_MEMORY) {
        /* Get Memory usage */
        mu_end  = zend_memory_usage(0 TSRMLS_CC);
        pmu_end = zend_memory_peak_usage(0 TSRMLS_CC);

        /* Bump Memory stats in the stats hashtable */
        hp_add_value(stats, "mu",  mu_end - top->mu_start_hprof    TSRMLS_CC);
        hp_add_value(stats, "pmu", pmu_end - top->pmu_start_hprof  TSRMLS_CC);
    }
}


/**
 * ***************************
 * PHP EXECUTE/COMPILE PROXIES
 * ***************************
 */

/**
 * Tideways enable replaced the zend_execute function with this
 * new execute function. We can do whatever profiling we need to
 * before and after calling the actual zend_execute().
 *
 * @author hzhao, kannan
 */
#if PHP_VERSION_ID >= 70000
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data) {
    zend_execute_data *real_execute_data = execute_data;
#elif PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute (zend_op_array *ops TSRMLS_DC) {
    zend_execute_data *execute_data = EG(current_execute_data);
    zend_execute_data *real_execute_data = execute_data;
#else
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data TSRMLS_DC) {
    zend_op_array *ops = execute_data->op_array;
    zend_execute_data    *real_execute_data = execute_data->prev_execute_data;
#endif
    char          *func = NULL;

    if (!TWG(enabled)|| (TWG(tideways_flags) & TIDEWAYS_FLAGS_NO_USERLAND) > 0) {
#if PHP_VERSION_ID < 50500
        _zend_execute(ops TSRMLS_CC);
#else
        _zend_execute_ex(execute_data TSRMLS_CC);
#endif
        return;
    }

    /* BEGIN PROFILING */
    int should_pop = 0;
    if (TWG(num_entries) < MAX_PROF_DEPTH+1) {
        func = hp_get_function_name(real_execute_data TSRMLS_CC);
        if (!func) {
#if PHP_VERSION_ID < 50500
            _zend_execute(ops TSRMLS_CC);
#else
            _zend_execute_ex(execute_data TSRMLS_CC);
#endif
            return;
        }
        BEGIN_PROFILING(&TWG(entries), func, real_execute_data);
        should_pop = 1;
        TWG(num_entries)++;
    }

#if PHP_VERSION_ID < 50500
    _zend_execute(ops TSRMLS_CC);
#else
    _zend_execute_ex(execute_data TSRMLS_CC);
#endif
    if (should_pop) {
        END_PROFILING(&TWG(entries), real_execute_data);
        TWG(num_entries)--;
        efree(func);
    }
}

#undef EX
#define EX(element) ((execute_data)->element)

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 *
 * @author hzhao, kannan
 */

#if PHP_VERSION_ID >= 70000
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *return_value) {
#elif PHP_VERSION_ID < 50500
#define EX_T(offset) (*(temp_variable *)((char *) EX(Ts) + offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       int ret TSRMLS_DC) {
#else
#define EX_T(offset) (*EX_TMP_VAR(execute_data, offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       struct _zend_fcall_info *fci, int ret TSRMLS_DC) {
#endif
    char          *func = NULL;

    if (!TWG(enabled) || (TWG(tideways_flags) & TIDEWAYS_FLAGS_NO_BUILTINS) > 0) {
#if PHP_MAJOR_VERSION == 7
        execute_internal(execute_data, return_value TSRMLS_CC);
#elif PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
        execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
        return;
    }

    /* BEGIN PROFILING */
    int should_pop = 0;
    if (TWG(num_entries) < MAX_PROF_DEPTH+1) {
        func = hp_get_function_name(execute_data TSRMLS_CC);
        if (func) {
            BEGIN_PROFILING(&TWG(entries), func, execute_data);
            should_pop = 1;
            TWG(num_entries)++;
        }
    }

    if (!_zend_execute_internal) {
#if PHP_VERSION_ID >= 70000
        execute_internal(execute_data, return_value TSRMLS_CC);
#elif PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
        execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    } else {
        /* call the old override */
#if PHP_VERSION_ID >= 70000
        _zend_execute_internal(execute_data, return_value TSRMLS_CC);
#elif PHP_VERSION_ID < 50500
        _zend_execute_internal(execute_data, ret TSRMLS_CC);
#else
        _zend_execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    }

    if (should_pop) {
        END_PROFILING(&TWG(entries), execute_data);
        TWG(num_entries)--;
        efree(func);
    }
}

/**
 * Reset the timer to the new interval (in msec).
 * Return 0 on success.
 *
 * @author wei
 */
static int reset_timer(int which, int new_which, unsigned new_interval, void (*func)(int))
{
    int retVal = 0;
    struct itimerval it_val;
    if (new_which != which) {
        it_val.it_value.tv_sec = 0;
        it_val.it_value.tv_usec = 0;
        it_val.it_interval = it_val.it_value;
        if (setitimer(which, &it_val, NULL) < 0) {
            retVal = -2;
        }
        else {
            int old_sigint;
            int new_sigint;
            switch (new_which) {
                case ITIMER_PROF:
                    old_sigint = SIGPROF;
                    new_sigint = SIGPROF;
                    break;
                case ITIMER_VIRTUAL:
                    old_sigint = SIGVTALRM;
                    new_sigint = SIGVTALRM;
                    break;
                case ITIMER_REAL:
                defaut:
                    old_sigint = SIGALRM;
                    new_sigint = SIGALRM;
                    break;
            }
            /*signal(old_sigint, SIG_DFL);*/
            if (signal(new_sigint, func) == SIG_ERR) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
                php_printf("<br>");
#endif
                php_printf("Unable to catch SIG %d\n", new_sigint);
#endif
                retVal = -3;
            }
        }
    }
    if (retVal == 0) {
        it_val.it_value.tv_sec = new_interval / 1000;
        it_val.it_value.tv_usec = (new_interval * 1000) % 1000000;
        it_val.it_interval = it_val.it_value;
        if (setitimer(new_which, &it_val, NULL) < 0) {
            retVal = -1;
        }
    }
    return retVal;
}


static int find_line_number_for_current_execute_point(zend_execute_data *edata TSRMLS_DC)
{
    zend_execute_data *ptr = edata;
#if PHP_VERSION_ID >= 70000
    while (ptr && (!ptr->func || !ZEND_USER_CODE(ptr->func->type))) {
        ptr = ptr->prev_execute_data;
    }
#else
    while (ptr && !ptr->opline)
    {
        ptr = ptr->prev_execute_data;
    }
#endif

    if (ptr && ptr->opline) {
        return ptr->opline->lineno;
    }

    return 0;
}

/**
 * **************************
 * MAIN TIDEWAYS CALLBACKS
 * **************************
 */

/**
 * This function gets called at request init time.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static void hp_begin(long tideways_flags TSRMLS_DC)
{
    if (!TWG(enabled)) {
        TWG(enabled) = 1;
        TWG(tideways_flags) = (uint32)tideways_flags;

        /* one time initializations */
        hp_init_profiler_state(TSRMLS_C);

        /* start profiling from fictitious main() */
        TWG(root) = estrdup(ROOT_SYMBOL);
        TWG(root_hash_entry) = inline_hash_func(TWG(root), strlen(TWG(root)), 0);
        TWG(start_time) = cycle_timer();

        /* Catches SIGALRM sent whenever an ITIMER_ALRM timer expires */
        /*if (signal(SIGPROF, (void (*)(int))timeout_handler) == SIG_ERR) {*/
        /*if (signal(SIGVTALRM, (void (*)(int))timeout_handler) == SIG_ERR) {*/
        if (signal(SIGALRM, (void (*)(int))timeout_handler) == SIG_ERR) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("Unable to catch SIGALRM\n");
#endif
        }
        else {
            struct itimerval it_val;
            it_val.it_value.tv_sec = INTERVAL / 1000;
            it_val.it_value.tv_usec = (INTERVAL * 1000) % 1000000;
            it_val.it_interval = it_val.it_value;
            /* Starts a REAL timer, which counts down in wallclock (REAL) time */
            /*if (setitimer(ITIMER_PROF, &it_val, NULL) < 0) {*/
            /*if (setitimer(ITIMER_VIRTUAL, &it_val, NULL) < 0) {*/
            if (setitimer(ITIMER_REAL, &it_val, NULL) < 0) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
                php_printf("<br>");
#endif
                php_printf("Error calling settimer()\n");
#endif
            }
        }
        BEGIN_PROFILING(&TWG(entries), TWG(root), NULL);
        TWG(num_entries)++;
    }
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end(TSRMLS_D)
{
    /* Bail if not ever enabled */
    if (!TWG(ever_enabled)) {
        return;
    }

    /* Stop profiler if enabled */
    if (TWG(enabled)) {
        hp_stop(TSRMLS_C);
    }

    if (TWG(record_end_stat) == 0) {
#if !(defined(TRAINING) && TRAINING > 0)
        /* We do not store the stat of a Positive request */
        if (TWG(check_history_count) == 0)
#endif
        dump_stats_count(TSRMLS_C);
#if defined(ENABLE_RULE) && ENABLE_RULE > 0
        if (TWG(test_rule) > 0) {
            record_rule(0); /* REVOKE */
            time_t t = time(NULL);
#if defined(VERBOSE) && VERBOSE >= VERBOSE_WARNING
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("%d\tRevoking Rule!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif
#if (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)
            fprintf(TWG(log_f), "%d\tRevoking Rule!!! v_user_id=%s, uri=%s\n", t, TWG(v_user_id), SG(request_info).request_uri);
#endif // (defined(WRITE_LOG) && WRITE_LOG > 0) && (defined(REPORT_MODE) && REPORT_MODE > 0)

        }
#endif // defined(ENABLE_RULE) && ENABLE_RULE > 0
    }

    /* Clean up state */
    hp_clean_profiler_state(TSRMLS_C);
}

/**
 * Called from tideways_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop(TSRMLS_D)
{
    /* End any unfinished calls */
    while (TWG(entries)) {
        END_PROFILING(&TWG(entries), NULL);
        TWG(num_entries)--;
    }

    if (reset_timer(ITIMER_REAL, ITIMER_REAL, 0, NULL) < 0) {
#if defined(VERBOSE) && VERBOSE >= VERBOSE_ERROR
#if defined(PRINT_BR) && PRINT_BR > 0
        php_printf("<br>");
#endif
        php_printf("Error clearing timer\n");
#endif
    }

    if (TWG(root)) {
        efree(TWG(root));
        TWG(root) = NULL;
    }

    /* Stop profiling */
    TWG(enabled) = 0;
}

/**
 * Save a new rule on disk for the stat_db_mgr.py daemon to handle.
 *
 * @author wei
 */
static void record_rule(int type)
{
    time_t t = time(NULL);
    char stat_file_name[256];
    memset(stat_file_name, '\0', sizeof(stat_file_name));
    char *pch;
    pch = strrchr(TWG(php_file_name), '/');
    if (pch == NULL)
        return;
    sprintf(stat_file_name, "/var/log/rampart/db/%s-%s-%d-%d-%d.rule", pch+1, TWG(v_user_id), (int)t, TWG(pid), TWG(random_num));
    FILE *output_f = fopen(stat_file_name, "a");
    if (output_f == NULL)
        return;
    if (type == -1) {

    }
    switch (type) {
        case -2:
            fprintf(output_f, "RENEW\t%s\t%s\n", TWG(v_user_id), TWG(uri_key));
            break;
        case -1:
            fprintf(output_f, "KILL\t%s\t%s\n", TWG(v_user_id), TWG(uri_key));
            break;
        case 1:
            fprintf(output_f, "TEST\t%s\t%s\n", TWG(v_user_id), TWG(uri_key));
            break;
        case 0:
        default:
            fprintf(output_f, "REVOKE\t%s\t%s\n", TWG(v_user_id), TWG(uri_key));
            break;
    }
    fclose(output_f);
}

/**
 * Save the profiling stats on disk for the stat_db_mgr.py daemon to handle.
 *
 * @author wei
 */
static void dump_stats_count(TSRMLS_D)
{
    prof_entry_t **prof_entries; // List of prof_entry_t

    HashTable *ht = TWG_ARRVAL(TWG(stats_count));
    size_t count = zend_hash_num_elements(ht);
    size_t index = 0;
    int n = 0;

    time_t t = time(NULL);
    char stat_file_name[256];
    memset(stat_file_name, '\0', sizeof(stat_file_name));
    char *pch;
    pch = strrchr(TWG(php_file_name), '/');
    if (pch == NULL)
        return;
    sprintf(stat_file_name, "/var/log/rampart/db/%s-%s-%d-%d-%d.stat", pch+1, TWG(v_user_id), (int)t, TWG(pid), TWG(random_num));
    FILE *output_f = fopen(stat_file_name, "a");
    if (output_f == NULL)
        return;
    zend_ulong hash_entry;
    zval *stat_ht_val;

    HashTable *stat_ht;
    zend_ulong idx;
    zval *stat_array_val;

    HashTable *stat_array;
    zval *val;
    long value;

#if PHP_VERSION_ID < 70000
    uint   key_len;
    uint   stat_len;
    int    type;
    char *key;
    char *stat;
    zval **stat_ht_data;
    zval **stat_array_data;
    zval **val_data;
    for (zend_hash_internal_pointer_reset(ht);
        /*zend_hash_get_current_data(ht, (void **) &stat_ht_data) == SUCCESS;*/
        zend_hash_has_more_elements(ht) == SUCCESS;
        zend_hash_move_forward(ht)) {

        type = zend_hash_get_current_key_ex(ht, &key, &key_len, &hash_entry, 0, NULL);
        if (zend_hash_get_current_data(ht, (void **) &stat_ht_data) != SUCCESS)
            return;

        stat_ht_val = *stat_ht_data;
        stat_ht = HASH_OF(stat_ht_val);
        for (zend_hash_internal_pointer_reset(stat_ht);
            /*zend_hash_get_current_data(stat_ht, (void **) &stat_array_data) == SUCCESS;*/
            zend_hash_has_more_elements(stat_ht) == SUCCESS;
            zend_hash_move_forward(stat_ht)) {

            type = zend_hash_get_current_key_ex(stat_ht, &stat, &stat_len, &idx, 0, NULL);
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("%u\t%s", hash_entry, stat);
            fprintf(TWG(log_f), "%u\t%s", hash_entry, stat);
#endif
            /* It is important to write hash_entry as %ld!!! */
            fprintf(output_f, "%ld\t%s", hash_entry, stat);

            if (zend_hash_get_current_data(stat_ht, (void **) &stat_array_data) != SUCCESS)
                return;

            stat_array_val = *stat_array_data;
            stat_array = HASH_OF(stat_array_val);
            for (zend_hash_internal_pointer_reset(stat_array);
                zend_hash_get_current_data(stat_array, (void **) &val_data) == SUCCESS;
                zend_hash_move_forward(stat_array)) {

                val = *val_data;
                value = Z_LVAL_P(val);
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
                php_printf("\t%ld", value);
                fprintf(TWG(log_f), "\t%ld", value);
#endif
                fprintf(output_f, "\t%ld", value);
            }
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
            php_printf("\n");
            fprintf(TWG(log_f), "\n");
#endif
            fprintf(output_f, "\n");
        }
    }
#else // if PHP_VERSION_ID < 70000
    zend_string *key;
    zend_string *stat;
    ZEND_HASH_FOREACH_KEY_VAL(ht, hash_entry, key, stat_ht_val) {
        stat_ht = HASH_OF(stat_ht_val);
        ZEND_HASH_FOREACH_KEY_VAL(stat_ht, idx, stat, stat_array_val) {
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
#if defined(PRINT_BR) && PRINT_BR > 0
            php_printf("<br>");
#endif
            php_printf("%u\t%s", hash_entry, ZSTR_VAL(stat));
            fprintf(TWG(log_f), "%u\t%s", hash_entry, ZSTR_VAL(stat));
#endif
            /* It is important to write hash_entry as %ld!!! */
            fprintf(output_f, "%ld\t%s", hash_entry, ZSTR_VAL(stat));

            stat_array = HASH_OF(stat_array_val);
            ZEND_HASH_FOREACH_VAL(stat_array, val) {
                value = Z_LVAL_P(val);
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
                php_printf("\t%ld", value);
                fprintf(TWG(log_f), "\t%ld", value);
#endif
                fprintf(output_f, "\t%ld", value);
            } ZEND_HASH_FOREACH_END();
#if defined(WRITE_LOG) && WRITE_LOG> 0 && defined(VERBOSE) && VERBOSE >= VERBOSE_INFO
            php_printf("\n");
            fprintf(TWG(log_f), "\n");
#endif
            fprintf(output_f, "\n");
        } ZEND_HASH_FOREACH_END();
    } ZEND_HASH_FOREACH_END();
#endif // PHP_VERSION_ID < 70000
    fclose(output_f);
}

