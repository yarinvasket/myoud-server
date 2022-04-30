from flask import Flask, request
from flask_restful import Api, Resource
import random
import logging

from requests import session

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

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
        return 200


api.add_resource(Register, '/api/register')
api.add_resource(Login, 'api/login')

if __name__ == '__main__':
    app.run(debug=True)