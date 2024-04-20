# Hashcryption

## Problem Statement

AES ECB mode isn't very secure. But surely when I combine it with hashing it's going to be secure right? I'm so confident that i've even deployed a network service that allows you to do your own encryption using this technique!

Interact with the service at: `chals.t.cyberthon24.ctf.sg:32011`

Concept(s) Required:
- AES ECB
- MD5

## Solution

Taking a look at the server script:
```python
#! /usr/bin/python3

from Crypto.Hash import MD5
from Crypto.Cipher import AES
from binascii import unhexlify
import sys


KEY = open('aeskey', 'rb').read()


def read(prompt):
    write(prompt)
    data = sys.stdin.buffer.read()
    write('\n')

    return data


def write(prompt):
    try:
        sys.stdout.buffer.write(prompt)
    except TypeError:
        sys.stdout.buffer.write(prompt.encode('utf-8'))

    sys.stdout.flush()


def md5sum(data):
    md5 = MD5.new()
    md5.update(data)

    return md5.hexdigest()


def md5ify(data):
    return unhexlify(''.join([md5sum(bytes([byte])) for byte in data]))


def encrypt(data, key):
    hashed_data = md5ify(data)
    cipher = AES.new(key, AES.MODE_ECB)

    return cipher.encrypt(hashed_data)

data = read('[+] Data: ')
write('[+] Encrypted:\n')
write('----------------------------- START -------------------------------\n')
write(encrypt(data, KEY))
write('\n------------------------------ END --------------------------------')
```

The algorithm is relatively straightforward, it hashes each character of input with MD5, then encrypts it with AES_ECB.
Since the block size of MD5 and AES are the same (`128 bits`), each character is treated as one block.
There are also no initialization vectors (IV) or whatsoever, so a character will also always encrypt to the same piece of data.

This means we just send all the possible characters to the server, obtain a mapping between plaintext and the encrypted text, and use it to decrypt our flag.

```python
from pwn import *
import string

context.log_level = 'warn'


def send_char(char):
    r = remote("chals.t.cyberthon24.ctf.sg", 32011)
    r.sendlineafter(b'Data: ', char.encode())
    r.shutdown()

    r.recvlines(3)
    res = r.recvline().strip().hex()[:32]
    mapping[res] = char
    r.close()
    print(f"Progress: {len(mapping)}/{len(chars)}")


mapping = {}
chars = string.ascii_letters + string.digits + '{}_'
for char in chars:
    send_char(char)

with open('flag.txt.encrypted', 'rb') as f:
    enc = f.read().hex()
    for i in range(0, len(enc), 32):
        val = enc[i: i + 32]
        # There were some issues with the server return incomplete bytes
        # So this was a quick hack to resolve the issue
        for k, v in mapping.items():
            if val.startswith(k):
                print(v, end="")
```
