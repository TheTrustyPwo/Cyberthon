# Pemcakes

## Problem Statement

I have a PEM file, and an encrypted flag. But I seem to be lacking something.

# Solution

Decrypt the PEM file:

```shell
> openssl rsa -in pubkey.pem -text -inform PEM -pubin
Public-Key: (1024 bit)
Modulus:
    00:c3:ba:77:36:e1:15:a6:92:2b:31:fc:b5:10:3a:
    30:70:07:19:97:45:15:e5:bd:a0:96:68:a5:89:90:
    50:2f:5e:1b:8a:7b:64:2f:6a:0b:94:2f:6e:3e:a0:
    33:89:3a:49:e8:a0:48:63:c7:0a:62:f4:74:d8:2b:
    af:a0:bf:3e:0e:1c:9a:0f:9b:79:90:db:47:82:76:
    0d:88:64:20:17:4d:56:bc:e0:e6:e1:6e:38:f7:fc:
    d7:5b:ca:05:45:a1:68:6a:56:7d:9f:5b:b6:d6:bc:
    07:6f:f0:d0:8a:b4:c4:dd:53:23:8a:de:dd:b2:2d:
    b6:19:54:7a:45:e4:3d:8f:b7
Exponent: 2 (0x2)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDDunc24RWmkisx/LUQOjBwBxmX
RRXlvaCWaKWJkFAvXhuKe2QvaguUL24+oDOJOknooEhjxwpi9HTYK6+gvz4OHJoP
m3mQ20eCdg2IZCAXTVa84Obhbjj3/NdbygVFoWhqVn2fW7bWvAdv8NCKtMTdUyOK
3t2yLbYZVHpF5D2PtwIBAg==
-----END PUBLIC KEY-----
```

Immediately, we see the vulnerability: the public key being 2.
Let's analyse the math and see how we can solve for the original message.

`c = m^e (mod N)`

`m^e = c + kN`  where `k` is a non-negative integer.

Since `e` is extremely small in our case, we can brute force `k` to find `m`.

This is the full solution with python:
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import iroot

e = 2
N = bytes_to_long(bytes.fromhex("""
    00:c3:ba:77:36:e1:15:a6:92:2b:31:fc:b5:10:3a:
    30:70:07:19:97:45:15:e5:bd:a0:96:68:a5:89:90:
    50:2f:5e:1b:8a:7b:64:2f:6a:0b:94:2f:6e:3e:a0:
    33:89:3a:49:e8:a0:48:63:c7:0a:62:f4:74:d8:2b:
    af:a0:bf:3e:0e:1c:9a:0f:9b:79:90:db:47:82:76:
    0d:88:64:20:17:4d:56:bc:e0:e6:e1:6e:38:f7:fc:
    d7:5b:ca:05:45:a1:68:6a:56:7d:9f:5b:b6:d6:bc:
    07:6f:f0:d0:8a:b4:c4:dd:53:23:8a:de:dd:b2:2d:
    b6:19:54:7a:45:e4:3d:8f:b7
""".replace(':', '')))

with open('flag.txt.encrypted', 'rb') as f:
    c = bytes_to_long(f.read())

for k in range(100):
    m, success = iroot(c + k * N, e)
    if success:
        print(long_to_bytes(m))
        break
```