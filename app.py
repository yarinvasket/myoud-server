import base64
import hashlib
import logging
import math
import secrets
import sqlite3
import time

import bcrypt
import pgpy
from flask import (Flask, Response, jsonify, make_response, request,
                   stream_with_context)
from flask_restful import Api, Resource
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)

from functions import *
from queries import *

f = open('globalsalt.txt', 'r')
globalsalt = f.read()

chunk_size = 4096

logging.basicConfig(filename='log.log', encoding='utf-8', level=logging.DEBUG)

app = Flask(__name__)
api = Api(app)

class Register(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
            public_key = reqjson['public_key']
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
            faultyName(user_name)
            faultyString(public_key)
            faultyString(signature)
            faultyString(encrypted_private_key)
            faultyString(hashed_password)
            faultyString(salt2)
            spletPassword = hashed_password.split('$')
            salt = '$'.join(spletPassword[0:3] + [spletPassword[3][:22]])
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
        message = user_name + globalsalt
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

#       Salt and hash the password
        dhashed_password = bcrypt.hashpw(bytes(hashed_password, 'utf-8'), bcrypt.gensalt())

#       Create a file table for the user
        create_folder(user_name, cur)

#       Finally, register the user
        cur.execute(register_user, (\
            user_name, dhashed_password, salt,\
            salt2, public_key, encrypted_private_key\
        ))
        db.commit()
        db.close()

        logging.info('Register: user registered: ' + user_name)
        return 200

class GetSalt(Resource):
    def post(self):
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
            faultyName(user_name)
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
            return make_response(jsonify(message="user doesn't exist"), 404)

#       Finally, return the user's salt
        logging.info('Get salt: returned salt of user ' + user_name)
        return make_response(jsonify(salt=user[0][2]), 200)

class GetSalt2(Resource):
    def post(self):
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
            faultyName(user_name)
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
            return make_response(jsonify(message="user doesn't exist"), 404)

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
            faultyName(user_name)
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
        dhashed_password = user[0][1]
        if not bcrypt.checkpw(bytes(hashed_password, 'utf-8'), dhashed_password):
            logging.error('Login: incorrect password to user ' + user_name)
            return make_response(jsonify(message=\
                "incorrect login credentials"), 400)

#       Generate a token
        token = secrets.token_urlsafe(16)

#       Hash and save the token
        hashed_token = hashlib.sha256(bytes(token, 'utf-8')).hexdigest()
        if (session_timeout == 0):
            expiration = 0
        else:
            expiration = renew_token(session_timeout)
        cur.execute('insert into tokens values (?, ?, ?, ?)', \
            (hashed_token, user_name, expiration, session_timeout))
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
            faultyName(token)
        except Exception as e:
            logging.error('Logout formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('Logout: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Delete the token
        db, cur = connect_db()
        cur.execute("delete from tokens where token=:token",\
            {"token": hashed_token})
        
        db.commit()
        db.close()

        logging.info('Logout: user ' + user_name + ' logged out')
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
            faultyName(token)
            faultyPath(path)
        except Exception as e:
            logging.error('GetPath formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('GetPath: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)
        
#       Seperate between personal and shared files
        paths = path.split('/')
        if (paths[0] == "private"):
#           Select all files that are the sub directory of path
            actual_path = user_name + '/' + '/'.join(paths[1::])
            db, cur = connect_db()
            cur.execute("select name, date, key, isfolder, pathsig from :path",\
                {"path": actual_path})
            private = cur.fetchall()
            db.close()
            files = list()

#           Cut the path out of the name
            for file in private:
                name = file[0].split('/')[-1]
                date = file[1]
                key = file[2]
                isfolder = file[3]
                pathsig = file[4]
                files += (name, date, key, isfolder, pathsig)
            
#           Respond with the files
            logging.info('GetPath: User ' + user_name + ' got path ' + path)
            return make_response(jsonify(files), 200)

        elif (paths[0] == "shared"):
#           Get all files shared with user
            db, cur = connect_db()
            cur.execute("select name, date, key, sharesig from shares where username=:username",\
                {"username": user_name})
            shared = cur.fetchall()
            db.close()
            files = list()

#           Cut the path out of the name
            for file in shared:
                paths = file[0].split('/')
                name = paths[-1]
                date = file[1]
                key = file[2]
                isfolder = 0
                sharesig = file[3]
#               Username of the sharer
                username = paths[0]
                files += (name, date, key, isfolder, sharesig, username)

            logging.info('GetPath: User ' + user_name + ' got path ' + path)
            return make_response(jsonify(files), 200)

        else:
            logging.error('GetPath: path ' + path + ' doesn\'t begin with shared/ or private/')
            return make_response(jsonify(message='invalid format'), 400)

class CreateFolder(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            key = reqjson['key']
            path = reqjson['path']
            pathsig = reqjson['pathsig']
        except Exception as e:
            logging.error('CreateFolder formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyName(token)
            faultyString(key)
            faultyPath(path)
            faultyString(pathsig)
        except Exception as e:
            logging.error('CreateFolder formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('CreateFolder: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Assure that no folder exists
        actual_path = user_name + '/' + path
        db, cur = connect_db()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=':path'",\
            {"path": actual_path})
        if (cur.fetchall()):
            logging.error('CreateFolder: folder ' + actual_path + ' already exists')
            return make_response(jsonify(message='a folder with this name already exists'), 400)

#       Assure that no file exists
        parent_dir = '/'.join(actual_path.split('/')[0:-2])
        folder_name = path.split('/')[-1]
        try:
            cur.execute("select name from :path where name=:name",\
                {"path": parent_dir, "name": folder_name})
        except sqlite3.OperationalError as e:
            logging.error('CreateFolder: ' + str(e))
            return make_response(jsonify(message='invalid path'), 400)
        if (cur.fetchall()):
            logging.error('CreateFolder: file ' + actual_path + ' already exists')
            return make_response(jsonify(message='a file with this name already exists'), 400)

#       Create the folder
        cur.execute("insert into ? values (?, ?, ?, ?, ?, ?, ?)",\
            (parent_dir, folder_name, int(time.time()), key, 1, pathsig, None))
        create_folder(actual_path, cur)
        db.commit()
        db.close()

#       Respond with success
        logging.info('CreateFolder: folder ' + actual_path + ' was created for user ' + user_name)
        return 200

class DeleteFile(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            path = reqjson['path']
        except Exception as e:
            logging.error('DeleteFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyName(token)
            faultyPath(path)
        except Exception as e:
            logging.error('DeleteFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('DeleteFile: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Determine whether file or folder
        actual_path = user_name + '/' + path
        db, cur = connect_db()
        if (is_folder(actual_path, cur)):
            delete_folder(actual_path, cur)
            logging.info('DeleteFile: folder ' + actual_path + ' deleted')
        else:
            parent_dir = '/'.join(actual_path.split('/')[0:-2])
            folder_name = user_name + path
            cur.execute("delete from ? where name=?",\
                (parent_dir, folder_name))
            logging.info('DeleteFile: file ' + actual_path + ' deleted')
        db.commit()
        db.close()

#       Respond with success
        return 200

class ShareFile(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            path = reqjson['path']
            username = reqjson['username']
            file_key = reqjson['file_key']
            sharesig = reqjson['sharesig']
        except Exception as e:
            logging.error('ShareFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyName(token)
            faultyPath(path)
            faultyName(username)
            faultyString(file_key)
            faultyString(sharesig)
        except Exception as e:
            logging.error('ShareFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
#       NOTE: username is the username of the shared user,
#       while user_name is the username of the sharer
        if (not user_name):
            logging.error('ShareFile: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Assure that file exists
        db, cur = connect_db()
        actual_path = user_name + '/' + path
        file_name = path.split('/')[-1]
        cur.execute("select name from :path where name=:name and isfolder=0",\
            {"path": actual_path, "name": file_name})
        file = cur.fetchall()
        if (not file):
            logging.error('ShareFile: file ' + actual_path + ' doesn\'t exist')
            return make_response(jsonify(message='invalid path'), 400)
        
#       Assure that user exists
        cur.execute("select username from users where username=:username",\
            {"username": username})
        if (not cur.fetchall()):
            logging.error('ShareFile: user ' + username + ' doesn\'t exist')
            return make_response(jsonify(message='user doesn\'t exist'), 404)

#       Assure that file isn't already shared with user
        cur.execute("select username from shares where username=:username and name=:name",\
            {"username": username, "name": actual_path})
        if (cur.fetchall()):
            logging.error('ShareFile: file ' + actual_path + ' already shared with user ' + username)
            return make_response(jsonify(message='file already shared with user'), 400)

#       Share the file
        cur.execute("insert into shares values (?, ?, ?, ?, ?)",\
            (username, actual_path, int(time.time()), file_key, sharesig))
        db.commit()
        db.close()

#       Respond with success
        return 200

class GetPublicKey(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            user_name = reqjson['user_name']
        except Exception as e:
            logging.error('ShareFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyString(user_name)
        except Exception as e:
            logging.error('ShareFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that user exists
        db, cur = connect_db()
        cur.execute("select pk from users where username=:username",\
            {"username": user_name})
        pk = cur.fetchall()
        if (not pk):
            logging.error('GetPublicKey: user ' + user_name + ' doesn\'t exist')
            return make_response(jsonify(message='user doesn\'t exist'), 404)

#       Return the public key
        db.close()
        pk = pk[0][0]
        logging.info('GetPublicKey: returned public key of user ' + user_name)
        return make_response(jsonify(pk=pk), 200)

class UploadFile(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            path = reqjson['path']
            file_key = reqjson['file_key']
            pathsig = reqjson['pathsig']
            filesig = reqjson['filesig']
        except Exception as e:
            logging.error('UploadFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyName(token)
            faultyPath(path)
            faultyString(file_key)
            faultyString(pathsig)
            faultyString(filesig)
        except Exception as e:
            logging.error('UploadFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('UploadFile: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Open a stream
        stream_token = secrets.token_urlsafe(16)
        hashed_stream_token = hash_token(stream_token)
        actual_path = user_name + '/' + path
        db, cur = connect_db()
        cur.execute("insert into ustreams values (?, ?, ?, ?, ?)",\
            (hashed_stream_token, actual_path, file_key, pathsig, filesig))
        db.commit()
        db.close()

#       Respond with the stream token
        logging.info('UploadFile: responded with stream token: ' + hashed_stream_token)
        return make_response(jsonify(token=stream_token))

class UploadStream(Resource):
    def post(self, token):
#       Assure that the token field is valid
        try:
            faultyName(token)
        except Exception as e:
            logging.error('UploadStream formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Verify token
        hashed_token = hash_token(token)
        db, cur = connect_db()
        cur.execute("select path, key, pathsig, filesig from ustreams where token=:token",\
            {"token": hashed_token})
        file = cur.fetchall()
        if (not file):
            logging.error('UploadStream: token is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Get data from stream
        f = bytes()
        chunk_size = 4096
        while True:
            chunk = request.stream.read(chunk_size)
            if (len(chunk) == 0):
                break
            f += chunk

#       Extract file information
        path = file[0][0]
        key = file[0][1]
        pathsig = file[0][2]
        filesig = file[0][3]

#       Record file on db
        dirs = path.split('/')
        parent_dir = '/'.join(dirs[0:-1])
        file_name = dirs[-1]
        cur.execute("insert into %s values (?, ?, ?, ?, ?, ?)" % parent_dir,\
            (file_name, int(time.time()), key, 0, pathsig, filesig))
        db.commit()
        db.close()

        file = open('files/' + path, 'wb')
        file.write(f)
        file.close()

        return 200

class DownloadFile(Resource):
    def post(self):
#       Get input from request and assure that it is valid
        try:
            reqjson = request.json
            token = reqjson['token']
            path = reqjson['path']
        except Exception as e:
            logging.error('DownloadFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Assure that every field is valid
        try:
            faultyName(token)
            faultyPath(path)
        except Exception as e:
            logging.error('DownloadFile formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Validate token
        user_name, hashed_token = validate_token(token)
        if (not user_name):
            logging.error('DownloadFile: token ' + hashed_token + ' is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Open a stream
        stream_token = secrets.token_urlsafe(16)
        hashed_stream_token = hash_token(stream_token)
        actual_path = user_name + '/' + path
        db, cur = connect_db()
        cur.execute("insert into dstreams values (?, ?)",\
            (hashed_stream_token, actual_path))
        db.commit()

#       Get the key and the file sig
        dirs = actual_path.split('/')
        parent_dir = '/'.join(dirs[0:-1])
        file_name = dirs[-1]
        cur.execute("select key, filesig from %s where name=:name" % parent_dir,\
            {"name": file_name})
        file = cur.fetchall()
        db.close()
        if (not file):
            logging.error('DownloadFile: path ' + actual_path + ' is invalid')
            return make_response(jsonify(message='invalid path'), 404)
        key = file[0][0]
        filesig = file[0][1]

#       Respond with the stream token
        logging.info('DownloadFile: responded with stream token: ' + hashed_stream_token)
        return make_response(jsonify(token=stream_token, key=key, filesig=filesig))

class DownloadStream(Resource):
    def get(self, token):
#       Assure that the token field is valid
        try:
            faultyName(token)
        except Exception as e:
            logging.error('DownloadStream formatting: ' + str(e))
            return make_response(jsonify(message='invalid format'), 400)

#       Verify token
        hashed_token = hash_token(token)
        db, cur = connect_db()
        cur.execute("select path from dstreams where token=:token",\
            {"token": hashed_token})
        path = cur.fetchall()
        db.close()
        if (not path):
            logging.error('DownloadStream: token is invalid')
            return make_response(jsonify(message='invalid token'), 400)

#       Extract file content
        path = path[0][0]
        try:
            file = open('files/' + path, 'rb')
            f = file.read()
            file.close()
        except:
            logging.error('DownloadStream: path ' + path + ' is invalid')
            return make_response(jsonify(message='invalid path'), 404)

#       Stream iteration
        @stream_with_context
        def generate():
            chunks = math.floor(len(f) / chunk_size)
            for i in range(chunks):
                yield f[i * chunk_size : (i + 1) * chunk_size - 1]
            yield f[chunks * chunk_size :]

#       Stream file
        return Response(stream_with_context(generate()))

api.add_resource(Register, '/register')
api.add_resource(GetSalt, '/get_salt')
api.add_resource(GetSalt2, '/get_salt2')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(GetPath, '/get_path')
api.add_resource(CreateFolder, '/create_folder')
api.add_resource(DeleteFile, '/delete_file')
api.add_resource(ShareFile, '/share_file')
api.add_resource(UploadFile, '/upload_file')
api.add_resource(UploadStream, '/upload_stream/<string:token>')
api.add_resource(DownloadFile, '/download_file')
api.add_resource(DownloadStream, '/download_stream/<string:token>')

if __name__ == '__main__':
    app.run(debug=True)
