#! /usr/bin/python3
# coding=utf-8

import re
import csv
import queue
import random
import timeit
import hashlib
import threading
import multiprocessing
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor, as_completed

from cassandra import InvalidRequest
from cassandra.cluster import Cluster
from cassandra.query import tuple_factory

TABLE = "passkull"
KEYSPACE = "passkullspace"
DELIMITERS = {",": ","}
LINE_FORMAT = "^[a-zA-Z0-9\-\._À-ԯ]+@[A-Za-z0-9\-\._]+\.[A-Za-z0-9\-\._]+{0}[^{0}]+$"
NUM_OF_WORKERS = 2 * multiprocessing.cpu_count()
thread_lock = threading.Lock()
lines_queue = queue.Queue()
queue_lock = threading.Lock()
counter = 1


# FILES_PATH = r"/var/test/all_files/"

def run_func_in_threads_pool(func, args_lists):
    '''
    for each arg_list in args_lists opens a thread for func(*arg_list)
    return list of results
    '''
    pool = ThreadPool()
    threads_list = []
    for args_tup in args_lists:
        args_tup = tuple(args_tup)
        threads_list.append(pool.apply_async(func, args_tup))
    l = [t.get() for t in threads_list]
    return l


def create_values(line, delimiter, session, keyspace, table):
    global counter
    global thread_lock
    line = line.strip()
    line = line.replace(" ", "")
    reMails = '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-_]+\.[a-zA-Z0-9-.]+'

    try:
        try:
            mail_address, password = line.split(sep=delimiter, maxsplit=1)
            mail_address = re.findall(reMails, str(mail_address))[0]
            username, domain = mail_address.split(sep="@", maxsplit=1)
        except:
            password, mail_address = line.split(sep=delimiter, maxsplit=1)
            mail_address = re.findall(reMails, str(mail_address))[0]
            username, domain = mail_address.split(sep="@", maxsplit=1)
        keyp = f'{mail_address}:{password}'
        key = str(hashlib.md5(keyp.encode()).hexdigest())
        exist = search_if_ukey_in_database(value=key, session=session, keyspace=keyspace, table=table)
        if not exist:
            NTLM = str(hashlib.new('md4', password.encode('utf-16le')).hexdigest())
            MD5 = str(hashlib.md5(password.encode()).hexdigest())
            SHA1 = str(hashlib.sha1(password.encode()).hexdigest())
            with thread_lock:
                pre = session.prepare(f'INSERT INTO {keyspace}.{table} (ID, UserName, DomainName, Password, MD5, SHA1, NTLM, ukey)' + """ VALUES (?,?,?,?,?,?,?,?)""")
                counter += 1
                counter1 = counter
            session.execute(pre.bind((counter1, username.lower(), domain.lower(), password, MD5, SHA1, NTLM, key)))
        else:
            pass
    except Exception as e:
        print(f'ERROR: {line}. {e}')


def search_if_ukey_in_database(value, session, keyspace, table):
    value1 = set()
    value1.add(value)
    session.row_factory = tuple_factory
    pre = session.prepare(f'SELECT * FROM {keyspace}.{table} ' + """WHERE ukey=? ALLOW FILTERING""")
    rows = session.execute(pre.bind(value1))
    # rows = session.execute(select_cli)
    if len(rows.all()) > 0:
        return True
    else:
        return False


def get_regex_csv(key, value, session, keyspace, table, hashsearch=False):
    value = value.lower()
    if key == 'mail':
        username, domainname = value.split('@')
        pre = session.prepare(
            f'SELECT username,domainname,password FROM {keyspace}.{table} ' + """WHERE UserName=? and DomainName=? ALLOW FILTERING""")
        rows = session.execute(pre.bind((username, domainname))).all()
        # select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM  {keyspace}.{table} where username='{username}' and domainname='{domainname}' ALLOW FILTERING;"
    elif key in ("MD5", "NTLM", "SHA1") and hashsearch:
        value1 = set()
        value1.add('%%{0}%'.format(value))
        pre = session.prepare(
            f'SELECT password,MD5,NTLM,SHA1 FROM {keyspace}.{table} WHERE {key}' + """ LIKE ? ALLOW FILTERING""")
        rows = session.execute(pre.bind(value1))
        rows = rows.all()
    else:
        value1 = set()
        value1.add('%%{0}%'.format(value))
        pre = session.prepare(
            f'SELECT username,domainname,password FROM {keyspace}.{table} WHERE {key}' + """ LIKE ? ALLOW FILTERING""")
        rows = session.execute(pre.bind(value1))
        rows = rows.all()
    return tuple(rows)


def initilize_export_file(username, hashsearch=False):
    with open(f"/tmp/{username}_export.csv", "w", newline="") as export_file:
        writer = csv.writer(export_file)
        if hashsearch:
            writer.writerow((("Password", "MD5", "NTLM", "SHA1")))
        else:
            writer.writerow((("User Name", "Domain Name", "Password")))


def create_csv_file_to_export(key, value, session, keyspace, table, username, hashsearch=False):
    session.row_factory = tuple_factory
    if key == 'hash':
        keys = ("MD5", "NTLM", "SHA1")
    else:
        keys = []
        keys.append(key)
    lists_of_args = [[key, value, session, keyspace, table,hashsearch] for key in keys]
    rows_lists = run_func_in_threads_pool(get_regex_csv, lists_of_args)
    all_rows = []
    for rows_list in rows_lists:
        all_rows.extend(rows_list)
    all_rows = list(set(all_rows))
    # print(all_rows)
    with open(f"/tmp/{username}_export.csv", "a", newline="") as export_file:
        writer = csv.writer(export_file)
        writer.writerows(all_rows)

def get_regex(key, value, session, keyspace, table):
    value = value.lower()
    if key == 'mail':
        try:
            username, domainname = value.split('@')
            pre = session.prepare(f'SELECT username,domainname,password,md5,ntlm,sha1,ukey FROM {keyspace}.{table} ' + """WHERE UserName=? and DomainName=? ALLOW FILTERING""")
            rows = session.execute(pre.bind((username.lower(), domainname.lower()))).all()
            # select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM  {keyspace}.{table} where username='{username}' and domainname='{domainname}' ALLOW FILTERING;"
        except:
            rows = 'None'
    else:
        value1 = set()
        value1.add('%%{0}%'.format(value))
        pre = session.prepare(f'SELECT username,domainname,password,md5,ntlm,sha1,ukey FROM {keyspace}.{table} WHERE {key}' + """ LIKE ? ALLOW FILTERING""")
        rows = session.execute(pre.bind(value1))
        rows = rows.all()
    return rows


def search_in_database_regex(key, value, session, keyspace, table, username,  hashsearch=False):
    session.row_factory = tuple_factory
    if key == 'hash':
        keys = ("MD5", "NTLM", "SHA1")
    else:
        keys = []
        keys.append(key)
    lists_of_args = [[key, value, session, keyspace, table] for key in keys]
    rows_lists = run_func_in_threads_pool(get_regex, lists_of_args)
    all_rows = []
    if isinstance(rows_lists, list):
        for rows_list in rows_lists:
            all_rows.extend(rows_list)
    else:
        all_rows.extend(rows_lists)
    csv_args = [key, value, session, keyspace, table, username, hashsearch]
    t = threading.Thread(target=create_csv_file_to_export, args=tuple(csv_args))
    t.start()  # todo: this will run in the background, and will not return a result
    return all_rows


def get_count(session, keyspace, table, domain_name=None):
    if not domain_name:
        count_cli = f'SELECT COUNT(ID) FROM {keyspace}.{table}'
        domain_name = "total_count"  # todo: change for the name you want for the total count (without domain_name)
        count = session.execute(count_cli)
    else:
        domain = domain_name.lower()
        domainname = set()
        domainname.add('%%{0}%'.format(domain))
        pre = session.prepare(f'SELECT COUNT(ID) FROM {keyspace}.{table} ' + """where domainname LIKE ? ALLOW FILTERING""")
        count = session.execute(pre.bind(domainname))
    total_count = str(count.all()[0][0])
    return (domain_name, total_count)


def count_db_rows(session, keyspace, table, domain_name_list=('Gmail', 'Yahoo')):
    res_dict = {}
    try:
        lists_of_args = [[session, keyspace, table, None]]  # count_cli
        lists_of_args.extend([[session, keyspace, table, domain_name] for domain_name in domain_name_list])
        count_tuples = run_func_in_threads_pool(get_count, lists_of_args)
        for domain_name, count in count_tuples:
            res_dict[domain_name] = count
    except Exception as e:
        if f"Keyspace {keyspace} does not exist" in str(e):
            return {"total_count": "Error: PassDB DB does not exist"}
    return res_dict


def delete_row(session, keyspace, table, id):
    id1 = set()
    id1.add(id)
    pre = session.prepare(f'DELETE FROM {keyspace}.{table} ' + """WHERE ukey=?""")
    session.execute(pre.bind(id1))


def random_password(session, keyspace, table):
    username = None
    password = None
    try:
        count_cli = f'SELECT COUNT(ID) FROM {keyspace}.{table}'
        count = session.execute(count_cli)
        count = int(count.all()[0][0])
        password_of_the_day = None
        while not password_of_the_day:
            try:
                rand_id = set()
                rand_id.add(random.randint(1, count))
                pre = session.prepare(f'SELECT username, domainname, password FROM {keyspace}.{table} ' + """WHERE  id=?  ALLOW FILTERING""")
                password_of_the_day = session.execute(pre.bind(rand_id))
                password_of_the_day = list(password_of_the_day.all())[0]
                username = f' {password_of_the_day[0]}@{password_of_the_day[1]}'
                password = password_of_the_day[2]
            except:
                username = None
                password = None
    except Exception as e:
        if f"Keyspace {keyspace} does not exist" in str(e):
            password = "Error: PassDB DB does not exist"  # todo the error will return as password, and not printed to the screen here
    return username, password


def initilize_cassandra(session, keyspace, table):
    print("creating keyspace...")
    session.execute(f"CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = " + "{ 'class': 'SimpleStrategy', 'replication_factor': '1' }")
    print("setting keyspace...")
    session.set_keyspace(keyspace)
    print("creating table...")
    create_table_cli = f'CREATE TABLE IF NOT EXISTS {keyspace}.{table} (ID int, UserName text, DomainName text, Password text, MD5 text, SHA1 text, NTLM text, ukey text, PRIMARY KEY (ukey))'
    session.execute(create_table_cli)
    print("creating indexes...")
    indexex_options = "USING 'org.apache.cassandra.index.sasi.SASIIndex' WITH OPTIONS = {'mode': 'CONTAINS', " \
                      "'analyzer_class': 'org.apache.cassandra.index.sasi.analyzer.StandardAnalyzer', " \
                      "'case_sensitive': 'false'}"

    index_cli = [f'CREATE CUSTOM INDEX UserName_idx ON {keyspace}.{table} (UserName)',
                 f'CREATE CUSTOM INDEX DomainName_idx ON {keyspace}.{table} (DomainName)',
                 f'CREATE CUSTOM INDEX MD5_idx ON {keyspace}.{table} (MD5)',
                 f'CREATE CUSTOM INDEX SHA1_idx ON {keyspace}.{table} (SHA1)',
                 f'CREATE CUSTOM INDEX NTLM_idx ON {keyspace}.{table} (NTLM)',]

    for cli in index_cli:
        try:
            cli = f'{cli} {indexex_options}'
            session.execute(cli)
        except InvalidRequest as err:
            err = str(err).split('"')[1]
            print(f'ERROR: {err}')
            pass


def create_db_session():
    cluster = Cluster(['127.0.0.1'])
    session = cluster.connect()
    return session


def upload_worker(index, delimiter, session, keyspace, table):
    try:
        global lines_queue
        global queue_lock
        line = None
        while not line:
            with queue_lock:
                try:
                    if lines_queue.empty():
                        return
                    line = lines_queue.get(timeout=0.1)
                    create_values(line, delimiter, session, keyspace, table)
                    line = None
                except Exception as e:
                    print(f"Exception : {e} in thread {index}")
                    line = None
    except Exception as e:
        print(f"Error in thread {index}. {e}")


def read_file_and_upload(file_name, delimiter, keyspace, table):
    session = create_db_session()
    initilize_cassandra(session=session, keyspace=keyspace, table=table)
    global lines_queue
    global queue_lock

    # update counter to current max id
    global counter
    global thread_lock

    with thread_lock:
        try:
            counter = int(get_max_id_for_count(session, keyspace, table)) + 1
        except:
            counter = 1

    print("Start uploading...\n")
    start = timeit.default_timer()
    with open(file_name, encoding='utf-8',
              errors='ignore') as dump_file:
        for line in dump_file:
            with queue_lock:
                lines_queue.put(line)

        # open workers
        workers = []
        for i in range(NUM_OF_WORKERS):
            worker_thread = threading.Thread(target=upload_worker, args=(i, delimiter, session, keyspace, table,))
            workers.append(worker_thread)
            worker_thread.start()
    print('Ulpoad Time: ', timeit.default_timer() - start)
    print("Done...")


def get_max_id_for_count(session, keyspace, table):
    counter_cli = f"Select MAX(ID) FROM {keyspace}.{table}"
    counter = session.execute(counter_cli)
    return counter.one().system_max_id


def create_list_from_search_file(users_file_list):
  users_list = set()
  with open(users_file_list, encoding='utf-8', errors='ignore') as users_file:
      for user in users_file.readlines():
          try:
              user = user.strip()
              users_list.add(user)
          except:
              pass
  return list(users_list)

def search_list_in_db(file_list, session, keyspace, table, username, hashsearch, key):
    print('search list')
    initilize_export_file(username, hashsearch=hashsearch)
    users_list = list(set(create_list_from_search_file(file_list)))
    args_list = [(key, user, session, keyspace, table, username, hashsearch) for user in users_list]
    results_set = multi_search_list_in_db(func=search_in_database_regex, args_lists=args_list)
    print('finish search list')
    return list(results_set)


def multi_search_list_in_db(func, args_lists, num_workers=5):
    tasks = []
    results = []
    m = multiprocessing.Manager()
    lock = m.Lock()
    with ThreadPoolExecutor(max_workers=num_workers) as threads_executor:
        for args_tup in args_lists:
            tasks.append(threads_executor.submit(func, *args_tup))
        for task in as_completed(tasks):
            with lock:
                try:
                    result = task.result()[0]
                    results.append(result)
                except:
                    pass
    return results
