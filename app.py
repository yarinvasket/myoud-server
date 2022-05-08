from flask import Flask, request
from flask_restful import Api, Resource
import logging
import sqlite3
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
        try:
            user_name = request.form['user_name']
            public_key = request.form['public_key']
            signature = request.form['signature']
            encrypted_private_key = request.form['encrypted_private_key']
            hashed_password = request.form['hashed_password']
        except Exception as e:
            logging.error('Register formatting error: ' + str(e))
            return {'message':'invalid format'}, 400
        
        try:
            faultyString(user_name)
            faultyString(public_key)
            faultyString(signature)
            faultyString(encrypted_private_key)
            faultyString(hashed_password)
        except Exception as e:
            logging.error('Register formatting error: ' + str(e))
            return {'message':'invalid format'}, 400

        if (len(user_name) > 16 or len(user_name) <= 0):
            logging.error('Register error: user name ' + user_name + ' is too long')
            return {'message':'username is invalid'}, 400

        db, cur = connect_db()
        cur.execute(get_user, {"username": user_name})
        if (cur.fetchall()):
            logging.error('Register error: user ' + user_name + " already exists")
            return {'message':'username is taken'}, 400

        cur.execute(get_user_by_pk, {"pk": public_key})
        if (cur.fetchall()):
            logging.error('Register error: public key' + public_key + ' already exists')
            return {'message':'public key is taken'}, 400
        return 200

class Login(Resource):
    def post(self):
        try:
            user_name = request.form['user_name']
            hashed_password = request.form['hashed_password']
            session_timeout = request.form['session_timeout']
        except Exception as e:
            logging.error('Login formatting error: ' + str(e))
            return {'message':'invalid format'}, 400
        
        try:
            faultyString(user_name)
            faultyString(hashed_password)
            faultyType(session_timeout, int)
        except Exception as e:
            logging.error('Login formatting error: ' + str(e))
            return {'message':'invalid format'}, 400
        return 200

api.add_resource(Register, '/api/register')
api.add_resource(Login, '/api/login')

if __name__ == '__main__':
    app.run(debug=True)
