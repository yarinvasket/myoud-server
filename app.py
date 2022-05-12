import base64
import logging
import sqlite3

import bcrypt
import pgpy
from flask import Flask, jsonify, make_response, request
from flask_restful import Api, Resource
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)

from queries import *

allowedChars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./$')

user_name_salt = 'sZSRqcwWDNGv0BLg2xs7PO'

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

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
#       Get input from request and check that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
            public_key = reqjson['public_key']
            message = reqjson['message']
            signature = reqjson['signature']
            encrypted_private_key = reqjson['encrypted_private_key']
            hashed_password = reqjson['hashed_password']
        except Exception as e:
            logging.error('Register formatting error: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
            return make_response(jsonify(message="invalid format"), 400)
        
#       Check that every field is valid
        try:
            faultyString(user_name)
            faultyString(message)
            faultyString(encrypted_private_key)
            faultyString(hashed_password)
            salt = hashed_password.split('$')[3][:22]
            public_key_decoded = base64.b64decode(public_key)
            signature_decoded = base64.b64decode(signature)
        except Exception as e:
            logging.error('Register formatting error: ' + str(e) +\
                ' One of the fields is a wrong type.')
            return make_response(jsonify(message="invalid format"), 400)

#       Check validity of the username
        if (len(user_name) > 16 or len(user_name) <= 0):
            logging.error('Register error: user name ' + user_name + ' is too long')
            return make_response(jsonify(message="username is invalid"), 400)

#       Check that the username isn't taken
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        if (cur.fetchall()):
            logging.error('Register error: user ' + user_name + " already exists")
            return make_response(jsonify(message="username is taken"), 400)

#       Check that the public key isn't taken
        cur.execute(get_user_by_pk, {"pk": public_key})
        if (cur.fetchall()):
            logging.error('Register error: public key ' + public_key + ' already exists')
            return make_response(jsonify(message="public key is taken"), 400)

#       Check that the public key is valid
        try:
            key = pgpy.PGPKey()
            key.parse(public_key_decoded)
        except Exception as e:
            logging.error('Register formatting error: ' + str(e) +\
                ' Could not read public key ' + str(public_key_decoded))
            return make_response(jsonify(message="public key is invalid"), 400)

#       Check that the signature is valid
        try:
#           Make sure that this is a public key
            key = key.pubkey
            sig = pgpy.PGPSignature.from_blob(signature_decoded)
            ver = key.verify(message, sig)
            if (not ver):
                raise Exception('Could not verify message')
        except Exception as e:
            logging.error('Register error: invalid signature ' + str(signature_decoded) + ', ' +\
                message + ' ' + str(e))
            return make_response(jsonify(message="invalid signature"), 400)

#       Check that the message is valid
        if (message != user_name + user_name_salt):
            logging.error('Register error: invalid message ' + message +\
                ' for user name ' + user_name)
            return make_response(jsonify(message="invalid message"), 400)

#       Salt and hash the password
        dhashed_password = bcrypt.hashpw(bytes(hashed_password, 'utf-8'), bcrypt.gensalt())

#       Finally, register the user
        cur.execute(register_user, (\
            user_name, dhashed_password, salt,\
            public_key, encrypted_private_key\
        ))
        db.commit()
        db.close()

        logging.info('User registered: ' + user_name)
        return 200

class GetSalt(Resource):
    def get(self):
#       Get input from request and check that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
        except Exception as e:
            logging.error('Get salt formatting error: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
            return make_response(jsonify(message="invalid format"), 400)

#       Check that every field is valid
        try:
            faultyString(user_name)
        except Exception as e:
            logging.error('Get salt formatting error: ' + str(e) +\
                ' One of the fields is a wrong type.')
            return make_response(jsonify(message="invalid format"), 400)

#       Check that user exists
        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        user = cur.fetchall()
        if (not user):
            logging.error('Get salt error: user ' + user_name +\
                ' does not exist')
            return make_response(jsonify(message="user doesn't exist"), 400)

#       Finally, return the user's salt
        return make_response(jsonify(salt=user[0][2]), 200)

class Login(Resource):
    def post(self):
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
            hashed_password = reqjson['hashed_password']
            session_timeout = reqjson['session_timeout']
        except Exception as e:
            logging.error('Login formatting error: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)
        
        try:
            faultyString(user_name)
            faultyString(hashed_password)
            faultyType(session_timeout, int)
        except Exception as e:
            logging.error('Login formatting error: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)
        return 200

api.add_resource(Register, '/api/register')
api.add_resource(GetSalt, '/api/getsalt')
api.add_resource(Login, '/api/login')

if __name__ == '__main__':
    app.run(debug=True)
