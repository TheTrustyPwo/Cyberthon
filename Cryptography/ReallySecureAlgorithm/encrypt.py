from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

rsa = RSA.generate(2048)

with open('flag.txt', 'rb') as f:
    data = f.read()

ciphertext = pow(bytes_to_long(data), rsa.e, rsa.n)

with open('flag.txt.encrypted', 'wb') as f:
    f.write(long_to_bytes(ciphertext))

key_data = f'p = {rsa.p}\nq = {rsa.q}\ne = {rsa.e}'

with open('rsa.txt', 'w') as f:
    f.write(key_data)
