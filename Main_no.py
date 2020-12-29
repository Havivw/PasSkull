#! /usr/bin/python3
# coding=utf-8

import os
import csv
import hashlib
import random

from cassandra import InvalidRequest
from cassandra.cluster import Cluster
from cassandra.cqlengine import columns
from cassandra.query import tuple_factory
from cassandra.cqlengine.models import Model



TABLE = "PasSkull"
KEYSPACE ="passkullspace"
DELIMITERS = {",": ","}
LINE_FORMAT = "^[a-zA-Z0-9\-\._À-ԯ]+@[A-Za-z0-9\-\._]+\.[A-Za-z0-9\-\._]+{0}[^{0}]+$"
# FILES_PATH = r"/var/test/all_files/"


class Credentials(Model):
    __table_name_case_sensitive__ = True
    __keyspace__ = 'passkullspace'
    __table_name__ = 'passkull'
    ID = columns.Text(primary_key=True)
    UserName = columns.Text()
    Domain = columns.Text()
    Password = columns.Text() # plain text password
    MD5 = columns.Text()
    SHA1 = columns.Text()
    NTLM = columns.Text()
    key = columns.Text()


def extract_user_domain(mail):
    UserName = mail[:mail.find('@')]
    Domain = mail[mail.rfind('@') + 1:]
    return UserName, Domain


def create_values(line, delimiter, counter, session, keyspace, table):
    line = line.strip()
    line = line.replace(" ", "")
    try:
        mail_address, password = line.split(sep=delimiter, maxsplit=1)
        username, domain = extract_user_domain(mail=mail_address)
        keyp = f'{mail_address}:{password}'
        key = str(hashlib.md5(keyp.encode()).hexdigest())
        exist = search_if_ukey_in_database(value=key, session=session, keyspace=keyspace, table=table)
        if not exist:
            NTLM = str(hashlib.new('md4', password.encode('utf-16le')).hexdigest())
            MD5 = str(hashlib.md5(password.encode()).hexdigest())
            SHA1 = str(hashlib.sha1(password.encode()).hexdigest())
            insert_cli = f"INSERT INTO {keyspace}.{table} (ID, UserName, DomainName, Password, MD5, SHA1, NTLM, ukey) VALUES ('{counter}', '{username}', '{domain}', '{password}', '{MD5}', '{SHA1}', '{NTLM}', '{key}')"

            session.execute(insert_cli)
    except:
            print(f'ERROR: {line}')


def search_if_ukey_in_database( value, session, keyspace, table):
    session.row_factory = tuple_factory
    select_cli = f"SELECT * FROM {keyspace}.{table} WHERE ukey='{value}' ALLOW FILTERING"
    rows = session.execute(select_cli)
    if len(rows.all()) > 0:
        return True
    else:
        return False

def create_csv_file_to_export(key, value, session, keyspace, table, username):
    session.row_factory = tuple_factory
    rows = []
    if key == 'hash':
        select_cli = f"SELECT username,domainname,password FROM {keyspace}.{table} WHERE MD5 LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
        select_cli = f"SELECT username,domainname,password FROM {keyspace}.{table} WHERE NTLM LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
        select_cli = f"SELECT username,domainname,password FROM {keyspace}.{table} WHERE SHA1 LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
    else:
        select_cli = f"SELECT username,domainname,password FROM {keyspace}.{table} WHERE {key} LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
    with open(f"/tmp/{username}_export.csv", "w", newline="") as export_file:
        writer = csv.writer(export_file)
        writer.writerow((("User Name", "Domain Name", "Password")))
        writer.writerows(rows)


def search_in_database_regex(key, value, session, keyspace, table, username):
    session.row_factory = tuple_factory
    rows = []
    if key == 'hash':
        select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM {keyspace}.{table} WHERE MD5 LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
        select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM {keyspace}.{table} WHERE NTLM LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
        select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM {keyspace}.{table} WHERE SHA1 LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
    else:
        select_cli = f"SELECT username,domainname,password,md5,ntlm,sha1,id FROM {keyspace}.{table} WHERE {key} LIKE '%%{value}%' ALLOW FILTERING"
        rows.extend(session.execute(select_cli).all())
    create_csv_file_to_export(key, value, session, keyspace, table, username) # multi treads (send to backgroud)
    return rows


def count_db_rows(session, keyspace, table):
    try:
        count_cli = f'SELECT COUNT(ID) FROM {keyspace}.{table}'
        count = session.execute(count_cli)
        count = str(count.all()[0][0])
    except Exception as e :
        if f"Keyspace {keyspace} does not exist" in str(e):
            count = "Error: PassDB DB does not exist"
    return count


def delete_row(session, keyspace, table, id):
    delete_cli = f'DELETE FROM {keyspace}.{table} WHERE ID = \'{id}\' '
    print(delete_cli)
    session.execute(delete_cli)

def random_password(session, keyspace, table):
    try:
        count_cli = f'SELECT COUNT(ID) FROM {keyspace}.{table}'
        count = session.execute(count_cli)
        count = int(count.all()[0][0])
        password_of_the_day = None
        while not password_of_the_day:
            try:
                rand_id = random.randint(1, count)
                select_cli = f"SELECT username,domainname,password FROM {keyspace}.{table} WHERE  id='{rand_id}'  ALLOW FILTERING"
                password_of_the_day = list(session.execute(select_cli).all()[0])
                password_of_the_day = f'User Name: {password_of_the_day[0]}@{password_of_the_day[1]} Password: {password_of_the_day[2]}'
            except:
                password_of_the_day = None
    except Exception as e:
        if f"Keyspace {keyspace} does not exist" in str(e):
            password_of_the_day = "Error: PassDB DB does not exist"
    return password_of_the_day


def initilize_cassandra(session, keyspace, table):
    print("creating keyspace...")
    session.execute(f"CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = "+"{ 'class': 'SimpleStrategy', 'replication_factor': '1' }")
    print("setting keyspace...")
    session.set_keyspace(keyspace)
    print("creating table...")
    create_table_cli = f'CREATE TABLE IF NOT EXISTS {keyspace}.{table} (ID text, UserName text, DomainName text, Password text, MD5 text, SHA1 text, NTLM text, ukey text, PRIMARY KEY (ID))'
    session.execute(create_table_cli)
    print("creating indexes...")
    indexex_options = "USING 'org.apache.cassandra.index.sasi.SASIIndex' WITH OPTIONS = {'mode': 'CONTAINS', " \
                      "'analyzer_class': 'org.apache.cassandra.index.sasi.analyzer.StandardAnalyzer', " \
                      "'case_sensitive': 'false'}"
    index_cli = ['CREATE CUSTOM INDEX UserName_idx ON passkullspace.PasSkull ( UserName )',
                 'CREATE CUSTOM INDEX DomainName_idx ON passkullspace.PasSkull ( DomainName )',
                 'CREATE CUSTOM INDEX MD5_idx ON passkullspace.PasSkull ( MD5 )',
                 'CREATE CUSTOM INDEX SHA1_idx ON passkullspace.PasSkull ( SHA1 )',
                 'CREATE CUSTOM INDEX NTLM_idx ON passkullspace.PasSkull ( NTLM )',
                 'CREATE CUSTOM INDEX ukey_idx ON passkullspace.PasSkull ( ukey )']
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


def read_file_and_upload(file_name, delimiter, keyspace, table):
    session = create_db_session()
    initilize_cassandra(session=session, keyspace=keyspace, table=table)
    counter = 0
    print("Start uploading...\n")
    with open(file_name, encoding='utf-8', errors='ignore') as dump_file: # multi treads
        for line in dump_file:
            counter += 1
            create_values(line, delimiter, counter, session, keyspace, table)
    print("Done...")
