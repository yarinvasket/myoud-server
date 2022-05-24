import sqlite3

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
        uuid          text primary key,
        user          text,
        expiration    integer,
        timeout       integer)'''

q3 = '''CREATE TABLE files(
        name          text primary key,
        content       blob,
        date          integer,
        usernameskeys JSON1)'''

cur.execute(q1)
cur.execute(q2)
cur.execute(q3)

db.commit()
db.close()
