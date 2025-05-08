from pwn import *
import string

context.log_level = 'warn'


def send_char(char):
    r = remote("chals.t.cyberthon25.ctf.sg", 32011)
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