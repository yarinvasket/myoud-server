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

f = open('globalsalt.txt', 'r')
globalsalt = f.read()

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

def renew_token(timeout: int):
    return int(time.time()) + timeout

def connect_db():
    db = sqlite3.connect('database.db')
    cur = db.cursor()
    return db, cur

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
        hashed_token = hashlib.sha256(token)
        if (session_timeout == 0):
            expiration = 0
        else:
            expiration = renew_token(session_timeout)
        cur.execute('insert into tokens values (?, ?, ?, ?)', \
            hashed_token, user_name, expiration, session_timeout)

#       Respond with the token, public key and encrypted private key
        logging.info('Login: user logged in: ' + user_name)
        return make_response(jsonify(token=token, pk=user[0][4], sk=user[0][5]))

api.add_resource(Register, '/api/register')
api.add_resource(GetSalt, '/api/get_salt')
api.add_resource(GetSalt2, '/api/get_salt2')
api.add_resource(Login, '/api/login')

if __name__ == '__main__':
    app.run(debug=True)
