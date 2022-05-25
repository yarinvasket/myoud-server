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
        token         text primary key,
        user          text,
        expiration    integer,
        timeout       integer)'''

q4 = '''CREATE TABLE shares(
        username      text primary key,
        key           text,
        name          text,
        date          integer)'''

cur.execute(q1)
cur.execute(q2)
cur.execute(q4)

db.commit()
db.close()
