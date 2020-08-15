import sqlite3, os, sys, time, traceback, random, signal
import numpy as np

DB_DIR = "/var/log/rampart/db/"
DATABASE = "stat.db"
WAL = False
RULE_LIFE_SPAN = 30
RULE_EXPIRY_TIME = 10

def getlocaltime():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def signal_term_handler(sig, frame):
    global conn
    current_time = getlocaltime()
    current_pid = os.getpid()
    msg = '%s\tPROCESS [%d] received SIGTERM!!! Cleaning up...' % (current_time, current_pid)
    current_time = time.time()
    stat_files = [f for f in os.listdir('.') if f.endswith('.stat') or f.endswith('.rule')]
    for f in stat_files:
        try:
            os.remove(f)
        except OSError as e:
            pass
    try:
        conn.rollback()
        conn.close()
    except Exception as e:
        pass
    current_time = getlocaltime()
    msg = '%s\tPROCESS [%d] terminated' % (current_time, current_pid)
    sys.stdout.flush()
    sys.exit()

def test_file_timestamp(f, end, ext):
    result = False
    if f.endswith(ext):
        parts = f.split('-')
        try:
            t = int(parts[-3])
        except Exception as e:
            print(e)
            print(parts)
            sys.exit(0)
        result = (t < end)
    return result

def process_rulefile(f, add_list, renew_list, test_list, remove_list):
    try:
        with open(f, 'r') as input_f:
            for line in input_f:
                try:
                    data = line[:-1].split('\t')
                except ValueError as e:
                    continue
                rule_type = data[0]
                uid = data[1]
                uri_key = data[2]
                keys = (uid, uri_key)
                if rule_type == 'KILL':
                    add_list.add(keys)
                elif rule_type == 'RENEW':
                    renew_list.add(keys)
                elif rule_type == 'TEST':
                    test_list.add(keys)
                elif rule_type == 'REVOKE':
                    remove_list.add(keys)
    except IOError as e:
        pass

def update_rule(cur, add_list, renew_list, test_list, remove_list):
    global conn
    add_queries = list()
    renew_queries = list()
    update_queries = list()
    remove_queries = list()
    current_time = time.time()
    local_time = getlocaltime()
    for i, v in enumerate(add_list):
        uid, uri_key = v
        status = 1 # KILL, ACTIVE
        count = 1
        cur.execute('SELECT ct FROM RULES WHERE uid=(?1) AND uri_key = (?2)', (uid, uri_key))
        row = cur.fetchone()
        if row is not None:
            count = int(row[0])
            count += 1 
        interval = count * RULE_EXPIRY_TIME
        expiry_time = current_time + interval
        print("%s\tSetting KILL rule for (%s, %s), interval=%.2f" % (local_time, uid, uri_key, interval))
        add_queries.append((uid, uri_key, expiry_time, count, status))
    for i, v in enumerate(renew_list):
        uid, uri_key = v
        interval = RULE_EXPIRY_TIME
        expiry_time = current_time + interval
        print("%s\tSetting RENEW rule for (%s, %s), interval=%.2f" % (local_time, uid, uri_key, interval))
        renew_queries.append((expiry_time, uid, uri_key))
    for i, v in enumerate(test_list):
        uid, uri_key = v
        status = 0 # TEST
        print("%s\tSetting TEST rule for (%s, %s)" % (local_time, uid, uri_key))
        update_queries.append((status, uid, uri_key))
    for i, v in enumerate(remove_list):
        uid, uri_key = v
        status = -1 # INACTIVE
        cur.execute('SELECT expiry FROM RULES WHERE uid=(?1) AND uri_key = (?2)', (uid, uri_key))
        row = cur.fetchone()
        timestamp = 0
        expiry_time = 0
        if row is not None:
            expiry_time = float(row[0])
        if expiry_time + RULE_LIFE_SPAN < current_time:
            print("%s\tRemoving rule for (%s, %s)" % (local_time, uid, uri_key))
            remove_queries.append(v)
        else:
            print("%s\tSetting REVOKE rule for (%s, %s)" % (local_time, uid, uri_key))
            update_queries.append((status, uid, uri_key))
    # Transaction is managed automatically, see https://docs.python.org/2/library/sqlite3.html#sqlite3-controlling-transactions
    if len(add_queries) > 0:
        cur.executemany("INSERT OR REPLACE INTO RULES VALUES (?1, ?2, ?3, ?4, ?5)", add_queries)
    if len(renew_queries) > 0:
        cur.executemany("UPDATE RULES SET expiry = (?1) WHERE uid = (?2) AND uri_key = (?3)", renew_queries)
    if len(update_queries) > 0:
        cur.executemany("UPDATE RULES SET status = (?1) WHERE uid = (?2) AND uri_key = (?3)", update_queries)
    if len(remove_queries) > 0:
        cur.executemany("DELETE FROM RULES WHERE uid = (?1) AND uri_key = (?2)", remove_queries)
    conn.commit()

def process_statfile(f, hash2stat):
    try:
        with open(f, 'r') as input_f:
            for line in input_f:
                try:
                    data = line[:-1].split('\t')
                except ValueError as e:
                    continue
                hash_entry = int(data[0])
                stat = data[1]
                stat_data = [int(d) for d in data[2:]]
                if hash_entry not in hash2stat:
                    hash2stat[hash_entry] = [stat_data]
                else:
                    hash2stat[hash_entry].append(stat_data)
    except IOError as e:
        pass

def process_stats(hash2stat, hash2merged_stat):
    for hash_entry, stat_list in hash2stat.items():
        values = []
        for stat in stat_list:
            values += stat
        cpu_sum = np.sum(values)
        ct_sum = len(values)
        var = np.var(values)
        hash2merged_stat[hash_entry] = [ct_sum, cpu_sum, var]

def query_old_stat(cur, hash2stat, hash2old_stat):
    for hash_entry in hash2stat.keys():
        cur.execute('SELECT ct, cpu, cpu_variance FROM PERF_RECORDS WHERE hash=?', (hash_entry,))
        row = cur.fetchone()
        if row is not None:
            hash2old_stat[hash_entry] = [int(row[0]), int(row[1]), float(row[2])]

def update_new_stat(cur, hash2stat, hash2old_stat):
    global conn
    new_stats = list()
    count = len(hash2stat)
    for hash_entry, stat in hash2stat.items():
        ct, cpu, var = stat
        if hash_entry in hash2old_stat:
            old_stat = hash2old_stat[hash_entry]
            ct_p, cpu_p, var_p = old_stat
            mean = 1.0 * cpu / ct
            mean_p = 1.0 * cpu_p / ct_p
            mean_n = 1.0 * (cpu_p + cpu) / (ct_p + ct)
            mean_sq_p = mean_p * mean_p
            mean_sq = mean * mean
            mean_sq_n = mean_n * mean_n
            var = (ct_p * (mean_sq_p + var_p) + ct * (mean_sq + var)) / (ct_p + ct) - mean_sq_n
            ct += ct_p
            cpu += cpu_p
        new_stats.append((hash_entry, ct, int(cpu), float(var)))
        #print("Inserting stat of hash=%u, %d" % (hash_entry, hash_entry))
    # Transaction is managed automatically, see https://docs.python.org/2/library/sqlite3.html#sqlite3-controlling-transactions
    if count > 0:
        cur.executemany("INSERT OR REPLACE INTO PERF_RECORDS VALUES (?1, ?2, ?3, ?4)", new_stats)
        conn.commit()

def main(argv):
    global conn
    signal.signal(signal.SIGTERM, signal_term_handler)
    parent_pid = os.getpid()
    last_time = 0
    log_file = "stat_db.log"
    #log_f = open(log_file, 'w')
    os.chdir(DB_DIR)

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS PERF_RECORDS (hash INTEGER PRIMARY KEY, ct INTEGER, cpu INTEGER, cpu_variance REAL)")
    cur.execute("DROP TABLE IF EXISTS RULES")
    cur.execute("CREATE TABLE IF NOT EXISTS RULES (uid TEXT, uri_key TEXT, expiry REAL, ct INTEGER, status INTEGER, PRIMARY KEY (uid, uri_key))")

    if WAL:
        conn.commit()
        conn.close()
    else:
        cur.execute("PRAGMA synchronous = OFF")
        cur.execute("PRAGMA journal_mode = MEMORY")
        #cur.execute("PRAGMA journal_mode = WAL")
        cur.execute("PRAGMA cache_size = 100000")

    should_sleep = True
    while True:
        try:
            current_time = time.time()
            if should_sleep and current_time - last_time < 1:
                time.sleep(min(1-(current_time-last_time), 1))
            else:
                rule_files = [f for f in os.listdir('.') if test_file_timestamp(f, current_time-1, '.rule')]
                kill_list = set()
                renew_list = set()
                test_list = set()
                remove_list = set()
                for f in rule_files:
                    process_rulefile(f, kill_list, renew_list, test_list, remove_list)
                num_rules = len(kill_list) + len(renew_list) + len(test_list) + len(remove_list)
                if num_rules > 0:
                    if WAL:
                        conn = sqlite3.connect(DATABASE)
                        cur = conn.cursor()
                        cur.execute("PRAGMA synchronous = OFF")
                        #cur.execute("PRAGMA journal_mode = MEMORY")
                        cur.execute("PRAGMA journal_mode = WAL")
                        cur.execute("PRAGMA cache_size = 100000")

                    update_rule(cur, kill_list, renew_list, test_list, remove_list)
                    num_rule_files = len(rule_files)
                    print('%s\tProcessed [%d] rule files with [%d] kill_rules, [%d] renew_rules, [%d] test_rules and [%d] remove_rules' % (getlocaltime(), num_rule_files, len(kill_list), len(renew_list), len(test_list), len(remove_list)))

                    if WAL:
                        conn.close()

                stat_files = [f for f in os.listdir('.') if test_file_timestamp(f, current_time-1, '.stat')]
                sample_size = min(len(stat_files), 100)
                should_sleep = sample_size == len(stat_files)
                stat_files = random.sample(stat_files, sample_size)
                sys.stdout.flush()
                hash2stat = dict()
                for f in stat_files:
                    process_statfile(f, hash2stat)
                if len(hash2stat) > 0:
                    hash2merged_stat =  dict()
                    process_stats(hash2stat, hash2merged_stat)

                    if WAL:
                        conn = sqlite3.connect(DATABASE)
                        cur = conn.cursor()
                        cur.execute("PRAGMA synchronous = OFF")
                        #cur.execute("PRAGMA journal_mode = MEMORY")
                        cur.execute("PRAGMA journal_mode = WAL")
                        cur.execute("PRAGMA cache_size = 100000")

                    hash2old_stat = dict()
                    num_entries = len(hash2merged_stat)
                    if num_entries > 0:
                        query_old_stat(cur, hash2merged_stat, hash2old_stat)
                        update_new_stat(cur, hash2merged_stat, hash2old_stat)
                        elapse = time.time() - current_time
                        num_stats = sum([len(v) for v in hash2stat.values()])
                        num_files = len(stat_files)
                        print('%s\tProcessed [%d] stat files with [%d] stats of [%d] unique hash entries in [%f] seconds' % (getlocaltime(), num_files, num_stats, num_entries, elapse))
                        sys.stdout.flush()
                    if WAL:
                        conn.close()
                    del hash2stat, hash2merged_stat, hash2old_stat
                for f in stat_files + rule_files:
                    try:
                        os.remove(f)
                    except OSError as e:
                        print(e)
                        pass
                last_time = current_time

        except (KeyboardInterrupt, Exception) as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            print(type(e))
            print(''.join('!! ' + line for line in lines))
            sys.stdout.flush()
            try:
                conn.rollback()
                if WAL:
                    conn.close()
            except Exception:
                pass
            if isinstance(e, KeyboardInterrupt):
                break
    if not WAL:
        conn.close()
    #log_f.close()

if __name__ == '__main__':
    main(sys.argv[1:])
