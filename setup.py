import sqlite3

db = sqlite3.connect('database.db')
cur = db.cursor()

q1 = '''CREATE TABLE users(
        username      text primary key,
        password      text,
        pk            text,
        sk            text,
        hierarchy     JSON1)'''

q2 = '''CREATE TABLE files(
        name          text primary key,
        content       blob,
        date          integer,
        usernameskeys JSON1)'''

cur.execute(q1)
cur.execute(q2)

db.commit()
db.close()
