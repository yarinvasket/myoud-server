import json
import logging
import sqlite3

import bcrypt
from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource

from queries import *

allowedChars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./$')

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

def connect_db():
    db = sqlite3.connect('database.db')
    cur = db.cursor()
    return db, cur

'''Throw error if not an int'''
def faultyType(var, typ : type):
    if (not isinstance(var, typ)):
        raise Exception('not a number')

'''Check if given string is in the allowed chars set. This is done in order to ensure no sql injection attacks are possible'''
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
            signature = reqjson['signature']
            encrypted_private_key = reqjson['encrypted_private_key']
            hashed_password = reqjson['hashed_password']
        except Exception as e:
            logging.error('Register formatting error: ' + str(e) +\
                ' The format isnt json, or is missing a field.')
#           TODO: DELETE THIS. POSSIBLE PASSWORD LOGGING
            logging.error(request.json)
            return make_response(jsonify(message="invalid format"), 400)
        
#       Check that every field is valid
        try:
            faultyString(user_name)
            faultyString(public_key)
            faultyString(signature)
            faultyString(encrypted_private_key)
            faultyString(hashed_password)
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
            logging.error('Register error: public key' + public_key + ' already exists')
            return make_response(jsonify(message="public key is taken"), 400)

#       TODO: check that the signature is valid

#       Salt and hash the password
        dhashed_password = bcrypt.hashpw(bytes(hashed_password, 'utf-8'), bcrypt.gensalt())

#       Finally, register the user
        cur.execute(register_user, (\
            user_name, dhashed_password,\
            public_key, encrypted_private_key\
        ))
        db.commit()
        db.close()

        return 200

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
api.add_resource(Login, '/api/login')

if __name__ == '__main__':
    app.run(debug=True)
