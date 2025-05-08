from pwn import *

r = remote('chals.t.cyberthon25.ctf.sg', 31011)
r.sendlineafter(b'>', b'equinox')
for t in [3, 6, 10, 15]:
    r.sendlineafter(b'>', str(t).encode())

x = [8, 4, 8, 0, 2]
s = "H4x0r"
out = ""
for i in range(5):
    t = ord(s[i]) - x[i]
    out += chr(t // 16)
r.sendlineafter(b'>', out.encode())

r.interactive()
