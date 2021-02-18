import time
import pickle
import threading

from Main import count_db_rows, random_password, KEYSPACE, TABLE


def get_db_status_interval(interval=60):
    while True:
        try:
            results = count_db_rows(keyspace=KEYSPACE, table=TABLE)
            with open("/data/Passkull/Web_Data/DB_status", 'wb') as db_status:
                pickle.dump(results, db_status)
            time.sleep(interval)
        except:
            continue


def password_of_the_hour(interval=60):
    while True:
        try:
            results = random_password(keyspace=KEYSPACE, table=TABLE)
            with open("/data/Passkull/Web_Data/Password_hour", 'wb') as password_file:
                pickle.dump(results, password_file)
                print('Password File Created!!!!!!')
            time.sleep(interval)
        except Exception as e:
            print(e)
            continue


def password_of_the_hour_run_thread():
    t = threading.Thread(target=password_of_the_hour, args=tuple())
    t.start()
    print("Create password of the hour file")


def get_db_status_interval_run_thread():
    t = threading.Thread(target=get_db_status_interval, args=tuple())
    t.start()
    print("Create DB Status file")



password_of_the_hour_run_thread()
get_db_status_interval_run_thread()