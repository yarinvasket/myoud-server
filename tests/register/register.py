import base64
import json

from requests import get, post

user_name = 'vasker32'
message = 'a'
signature = 'a'
encrypted_private_key = 'a'
hashed_password = '$2b$12$sZSRqcwWDNGv0BLg2xs7POMiNVksgSo6htKFu/mySbrLGfYL9zUHq'

def readEncodeBase64(file):
    f = open(file, 'rb')
    buffer = f.read()

    return base64.b64encode(buffer).decode()

# Read public key from file
public_key = readEncodeBase64('tests/register/public.key')

# Read signature from file
signature = readEncodeBase64('tests/register/signature.sig')

params = {
    "user_name": user_name,
    "public_key": public_key,
    "message": message,
    "signature": signature,
    "encrypted_private_key": encrypted_private_key,
    "hashed_password": hashed_password
}

headers = {
    "Content-Type": "application/json"
}

req = post('http://localhost:5000/api/register', json=params, headers=headers)

print(req.status_code)
print(req.json())
