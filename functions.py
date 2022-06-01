import hashlib
import logging
import sqlite3
import string
import time

lettersdigits = string.ascii_letters + string.digits + '_-'
allowedName = set(lettersdigits)
allowedPath = set(lettersdigits + '/')
allowedChars = set(lettersdigits + './$')

def connect_db():
    db = sqlite3.connect('database.db')
    cur = db.cursor()
    return db, cur

def hash_token(token):
    return hashlib.sha256(token).hexdigest()

def renew_token(timeout: int):
    return int(time.time()) + timeout

def validate_token(token):
    """Validates the token, returns either False or the username and hashed token

    Parameters
    ----------
    token: str
        the unhashed token to validate

    Returns
    ----------
    str
        the username this token belongs to
    str
        the sha256 hash of the token


    OR bool
        the validity of the token
    """

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

def faultyType(var, typ : type):
    """Validates the type

    Parameters
    ----------
    var: any
        the variable that gets checked
    typ: type
        the type to check against

    Raises
    ----------
    Exception
        if types do not match
    """
    if (not isinstance(var, typ)):
        raise Exception('not a number')

def faultyString(var):
    """Safe-checks the string for SQL injection

    Parameters
    ----------
    var: any
        the variable that gets checked

    Raises
    ----------
    Exception
        if var is not string or if one of the characters is not allowed
    """
    faultyType(var, str)

    for c in var:
        if (c not in allowedChars):
            raise Exception('string is not in allowedChars')

def faultyPath(var):
    """Safe-checks the string for regex injection

    Parameters
    ----------
    var: any
        the variable that gets checked

    Raises
    ----------
    Exception
        if var is not string or if one of the characters is not allowed
    """
    faultyType(var, str)

    for c in var:
        if (c not in allowedPath):
            raise Exception('string is not in allowedPath')

def faultyName(var : str):
    """Safe-checks the string for path injection or sqli

    Parameters
    ----------
    var: any
        the variable that gets checked

    Raises
    ----------
    Exception
        if var is not string or if one of the characters is not allowed
    """
    faultyType(var, str)

#   Assure no problematic characters
    for c in var:
        if (c not in allowedName):
            raise Exception('string is not in allowedName')

#   Assure username doesn't clash with one of the tables
    lower = var.lower()
    if lower == "users" or\
       lower == "tokens" or\
       lower == "shares" or\
       lower == "ustreams" or\
       lower == "dstreams":
        raise Exception('string clashes with table names')

def is_folder(path, cur : sqlite3.Cursor):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=':path'",\
            {"path": path})
    return cur.fetchall()

def delete_folder(path : str, cur : sqlite3.Cursor):
    """Deletes the folder and all of its subfiles in specified path. Must call db.commit() afterwards for this to take effect

    Parameters
    ----------
    path: str
        the server path to the folder. Is of the form "username/folder1/folder2/.../folder"
    db: sqlite3.Connection
        the sqlite3 database connection object
    cur: sqlite3.Cursor
        the sqlite3 cursor object to the database db
    """
#   Delete all subfolders
    cur.execute("select name from :path where isfolder=1",\
        {"path": path})
    folders = cur.fetchall()
    for folder in folders:
        delete_folder(path + '/' + folder, cur)

#   Delete the folder itself
    cur.execute("DROP TABLE :path",\
        {"path": path})
