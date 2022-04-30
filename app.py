from flask import Flask
from flask_restful import Api, Resource, reqparse
import random
import logging

app = Flask(__name__)
api = Api(app)

class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

api.add_resource(HelloWorld, '/api')

if __name__ == '__main__':
    app.run(debug=True)