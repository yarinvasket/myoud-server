import string
import secrets

alphabet = string.ascii_letters + string.digits

salt = ''.join(secrets.choice(alphabet) for i in range(16))

f = open('globalsalt.txt', 'w')
f.write(salt)
