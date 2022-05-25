import base64
import hashlib
import logging
import secrets
import sqlite3
import time

import bcrypt
import pgpy
from flask import Flask, jsonify, make_response, request
from flask_restful import Api, Resource
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)

from queries import *

allowedChars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./$')
allowedPath = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/')

f = open('globalsalt.txt', 'r')
globalsalt = f.read()

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

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

app = Flask(__name__)
api = Api(app)

class Register(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
            public_key = reqjson['public_key']
            message = reqjson['message']
            signature = reqjson['signature']
            encrypted_private_key = reqjson['encrypted_private_key']
            hashed_password = reqjson['hashed_password']
            salt2 = reqjson['salt2']
        except Exception as e:
            logging.error('Register formatting: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure that every field is valid
        try:
            faultyString(user_name)
            faultyString(message)
            faultyString(encrypted_private_key)
            faultyString(hashed_password)
            salt = hashed_password.split('$')[3][:22]
            public_key_decoded = base64.b64decode(public_key)
            signature_decoded = base64.b64decode(signature)
        except Exception as e:
            logging.error('Register formatting: ' + str(e) +\
                ' One of the fields is a wrong type.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure validity of the username
        if (len(user_name) > 16 or len(user_name) <= 0):
            logging.error('Register: user name ' + user_name + ' is too long')
            return make_response(jsonify(message="username is invalid"), 400)

#       Assure that the username isn't taken
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        if (cur.fetchall()):
            logging.error('Register: user ' + user_name + " already exists")
            return make_response(jsonify(message="username is taken"), 400)

#       Assure that the public key isn't taken
        cur.execute(get_user_by_pk, {"pk": public_key})
        if (cur.fetchall()):
            logging.error('Register: public key ' + public_key + ' already exists')
            return make_response(jsonify(message="public key is taken"), 400)

#       Assure that the public key is valid
        try:
            key = pgpy.PGPKey()
            key.parse(public_key_decoded)
        except Exception as e:
            logging.error('Register formatting: ' + str(e) +\
                ' Could not read public key ' + str(public_key_decoded))
            return make_response(jsonify(message="public key is invalid"), 400)

#       Assure that the signature is valid
        try:
#           Assure that this is a public key
            key = key.pubkey
            sig = pgpy.PGPSignature.from_blob(signature_decoded)
            ver = key.verify(message, sig)
            if (not ver):
                raise Exception('Could not verify message')
        except Exception as e:
            logging.error('Register: invalid signature ' + str(signature_decoded) + ', ' +\
                message + ' ' + str(e))
            return make_response(jsonify(message="invalid signature"), 400)

#       Assure that the message is valid
        if (message != user_name + globalsalt):
            logging.error('Register: invalid message ' + message +\
                ' for user name ' + user_name)
            return make_response(jsonify(message="invalid message"), 400)

#       Salt and hash the password
        dhashed_password = bcrypt.hashpw(bytes(hashed_password, 'utf-8'), bcrypt.gensalt())

#       Create a file table for the user
        cur.execute('''create table :path(
            name          text primary key,
            content       blob,
            date          integer,
            key           text,
            is_folder     integer)''',\
                {"path": user_name})

#       Finally, register the user
        cur.execute(register_user, (\
            user_name, dhashed_password, salt,\
            public_key, encrypted_private_key, salt2\
        ))
        db.commit()
        db.close()

        logging.info('Register: user registered: ' + user_name)
        return 200

class GetSalt(Resource):
    def get(self):
#       Get input from request and Assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
        except Exception as e:
            logging.error('Get salt formatting: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure that every field is valid
        try:
            faultyString(user_name)
        except Exception as e:
            logging.error('Get salt formatting: ' + str(e) +\
                ' One of the fields is a wrong type.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure that user exists
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        user = cur.fetchall()
        if (not user):
            logging.error('Get salt: user ' + user_name +\
                ' does not exist')
            return make_response(jsonify(message="user doesn't exist"), 400)

#       Finally, return the user's salt
        logging.info('Get salt: returned salt of user ' + user_name)
        return make_response(jsonify(salt=user[0][2]), 200)

class GetSalt2(Resource):
    def get(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
        except Exception as e:
            logging.error('Get salt 2 formatting: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure that every field is valid
        try:
            faultyString(user_name)
        except Exception as e:
            logging.error('Get salt 2 formatting: ' + str(e) +\
                ' One of the fields is a wrong type.')
            return make_response(jsonify(message="invalid format"), 400)

#       Assure that user exists
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        user = cur.fetchall()
        if (not user):
            logging.error('Get salt 2: user ' + user_name +\
                ' does not exist')
            return make_response(jsonify(message="user doesn't exist"), 400)

#       Finally, return the user's salt
        logging.info('Get salt 2: returned salt of user ' + user_name)
        return make_response(jsonify(salt2=user[0][3]), 200)

class Login(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
            hashed_password = reqjson['hashed_password']
            session_timeout = reqjson['session_timeout']
        except Exception as e:
            logging.error('Login formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyString(user_name)
            faultyString(hashed_password)
            faultyType(session_timeout, int)
        except Exception as e:
            logging.error('Login formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that the user exists
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        user = cur.fetchall()
        if (not user):
            logging.error('Login: user ' + user_name +\
                ' does not exist')
            return make_response(jsonify(message=\
                "incorrect login credentials"), 400)
        
#       Verify the password
        dhashed_password = bytes(user[0][1], 'utf-8')
        if not bcrypt.checkpw(bytes(hashed_password, 'utf-8'), dhashed_password):
            logging.error('Login: incorrect password to user ' + user_name)
            return make_response(jsonify(message=\
                "incorrect login credentials"), 400)

#       Generate a token
        token = str(secrets.token_bytes(16), 'utf-8')

#       Hash and save the token
        hashed_token = hashlib.sha256(token).hexdigest()
        if (session_timeout == 0):
            expiration = 0
        else:
            expiration = renew_token(session_timeout)
        cur.execute('insert into tokens values (?, ?, ?, ?)', \
            hashed_token, user_name, expiration, session_timeout)
        db.commit()
        db.close()

#       Respond with the token, public key and encrypted private key
        logging.info('Login: user logged in: ' + user_name)
        return make_response(jsonify(token=token, pk=user[0][4], sk=user[0][5]))

class Logout(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
        except Exception as e:
            logging.error('Logout formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyString(token)
        except Exception as e:
            logging.error('Logout formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Hash the token to delete
        hashed_token = hash_token(token)

#       Delete the token
        db, cur = connect_db()
        cur.execute("delete from tokens where token=:token",\
            {"token": hashed_token})

        return 200

class GetPath(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            path = reqjson['path']
        except Exception as e:
            logging.error('GetPath formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyString(token)
            faultyPath(path)
        except Exception as e:
            logging.error('GetPath formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('GetPath: token ' + hashed_token + ' is invalid')
        
#       Seperate between personal and shared files
        paths = path.split('/')
        if (paths[0] == "private"):
#           Select all files that are the sub directory of path
            actual_path = user_name + '/' + '/'.join(paths[1::])
            db, cur = connect_db()
            cur.execute("select name, date, key, is_folder from :path",\
                {"path": actual_path})
            files = cur.fetchall()
            db.close()

#           Cut the path out of the name
            for i in range(len(files)):
                files[i][0] = files[i][0].split('/')[-1]
            
#           Respond with the files
            logging.info('GetPath: User ' + user_name + ' got path ' + path)
            return make_response(jsonify(files), 200)

        elif (paths[0] == "shared"):
#           Get all files shared with user
            db, cur = connect_db()
            cur.execute("select key, name, date from shares where username=:username",\
                {"username": user_name})
            shared = cur.fetchall()
            db.close()

#           Cut the path out of the name
            for i in range(len(shared)):
                shared[i][1] = shared[i][1].split('/')[-1]

            logging.info('GetPath: User ' + user_name + ' got path ' + path)
            return make_response(jsonify(shared), 200)

        else:
            logging.error('GetPath: path ' + path + ' doesn\'t begin with shared/ or private/')
            return make_response(jsonify(message='invalid format'), 400)

api.add_resource(Register, '/api/register')
api.add_resource(GetSalt, '/api/get_salt')
api.add_resource(GetSalt2, '/api/get_salt2')
api.add_resource(Login, '/api/login')
api.add_resource(Logout, '/api/logout')
api.add_resource(GetPath, '/api/get_path')

if __name__ == '__main__':
    app.run(debug=True)
