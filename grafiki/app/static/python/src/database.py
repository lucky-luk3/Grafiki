import sqlite3
import os
from sqlite3 import Error
from django.db import connection


def sql_connection():
    try:
        #con = sqlite3.connect('grafiki.db', isolation_level=None)
        cursor = connection.cursor()

        #con.execute('pragma journal_mode=wal;')
        return cursor

    except Error:
        print(Error)

def sql_execute(con, query):
    cursorObj = con.cursor()
    cursorObj.execute(query)
    con.commit()
    cursorObj.close()

def sql_execute_select(con, query):
    cursorObj = con.cursor()
    cursorObj.execute(query)
    rows = cursorObj.fetchall()
    con.commit()
    cursorObj.close()
    return rows

def sql_initialitation(cursor):
    cursor.execute('DELETE from public."Processes";')
    cursor.execute('DELETE from public."Actions";')
    cursor.execute('DELETE from public."Connections";')
    cursor.execute('DELETE from public."DNSQuery";')
    cursor.execute('DELETE from public."DNSResolution";')
    cursor.execute('DELETE from public."Files";')
    cursor.execute('DELETE from public."Pipes";')
    cursor.execute('DELETE from public."RegistryKeys";')
    cursor.execute('DELETE from public."Threads";')
    cursor.execute('DELETE from public."Users";')
    cursor.execute('DELETE from public."PSEvents";')

def sql_todisk(con, path):
    if os.path.exists('databases/'+path):
        os.remove('databases/'+path)

    c2 = sqlite3.connect('databases/'+path)
    with c2:
        for line in con.iterdump():
            if line not in ('BEGIN;', 'COMMIT;'):  # let python handle the transactions
                c2.execute(line)
    c2.commit()
    c2.close()