import hashlib
import logging
import sqlite3
import time

allowedChars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./$')
allowedPath = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/')

def connect_db():
    db = sqlite3.connect('database.db')
    cur = db.cursor()
    return db, cur

def hash_token(token):
    return hashlib.sha256(token).hexdigest()

def renew_token(timeout: int):
    return int(time.time()) + timeout

def validate_token(token):
#   Hash the token since the database stores hashed tokens
    hashed_token = hash_token(token)

#   Check that the token exists for the user
    db, cur = connect_db()
    cur.execute("select * from tokens where token=:token",\
        {"token": hashed_token})
    user = cur.fetchall()
    if (not user):
        logging.error('Validate token: token ' + hashed_token + ' is not in the tokens table')
        return False

#   Check that the token is not expired
    expiration = user[0][2]
    if (0 < expiration < int(time.time())):
        logging.error('Validate token: token ' + hashed_token + ' has expired in' + expiration)
        return False

#   Renew the token
    timeout = user[0][3]
    new_expiration = renew_token(timeout)
    cur.execute("update tokens set expiration=:expiration where token=:token",\
        {"expiration": new_expiration, "token": hashed_token})
    db.commit()
    db.close()

    return user[0][1], hashed_token

# Throw error if not of type
def faultyType(var, typ : type):
    if (not isinstance(var, typ)):
        raise Exception('not a number')

# Check if given string is in the allowed chars set. This is done in order to ensure no sql injection attacks are possible
def faultyString(var):
    faultyType(var, str)

    for c in var:
        if (c not in allowedChars):
            raise Exception('string is not in allowedChars')

# Check if a given string is in the allowed path set. Prevents regex injection
def faultyPath(var):
    faultyType(var, str)

    for c in var:
        if (c not in allowedPath):
            raise Exception('string is not in allowedPath')

def is_folder(path, cur : sqlite3.Cursor):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=':path'",\
            {"path": path})
    return cur.fetchall()

# Deletes the folder in specified path. Must call db.commit() afterwards for this to take effect
def delete_folder(path, db : sqlite3.Connection, cur : sqlite3.Cursor):
#   Delete all subfolders
    cur.execute("select name from :path where is_folder=1",\
        {"path": path})
    folders = cur.fetchall()
    for folder in folders:
        delete_folder(path + '/' + folder, db, cur)

#   Delete the folder itself
    cur.execute("DROP TABLE :path",\
        {"path": path})
