import sqlite3
import os

os.mkdir('files')

db = sqlite3.connect('database.db')
cur = db.cursor()

q1 = '''CREATE TABLE users(
        username      text primary key,
        password      text,
        salt          text,
        salt2         text,
        pk            text,
        sk            text)'''

q2 = '''CREATE TABLE tokens(
        token         text primary key,
        user          text,
        expiration    integer,
        timeout       integer)'''

q3 = '''CREATE TABLE shares(
        username      text,
        path          text,
        name          text,
        date          integer,
        key           text,
        sharesig      text)'''

q4 = '''CREATE TABLE ustreams(
        token         text primary key,
        path          text,
        key           text,
        pathsig       text,
        filesig       text)'''

q5 = '''CREATE TABLE dstreams(
        token         text primary key,
        path          text)'''

cur.execute(q1)
cur.execute(q2)
cur.execute(q3)
cur.execute(q4)
cur.execute(q5)

db.commit()
db.close()
