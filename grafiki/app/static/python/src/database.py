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
    cursor.execute('DELETE from "Processes";')
    cursor.execute('DELETE from "Actions";')
    cursor.execute('DELETE from "Connections";')
    cursor.execute('DELETE from "DNSQuery";')
    cursor.execute('DELETE from "DNSResolution";')
    cursor.execute('DELETE from "Files";')
    cursor.execute('DELETE from "Pipes";')
    cursor.execute('DELETE from "RegistryKeys";')
    cursor.execute('DELETE from "Threads";')
    cursor.execute('DELETE from "Users";')
    cursor.execute('DELETE from "PSEvents";')

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