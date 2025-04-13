from random import randint
from pwnlib.util.fiddling import xor

KEY_LENGTH = 24

with open("flag.txt", "rb") as f:
    data = f.read()

key = bytes([randint(0, 0xFF) for i in range(KEY_LENGTH)])
data = xor(key, b"Here is the decrypted flag: " + data)

with open("flag.txt.encrypted", "wb") as f:
    f.write(data)
