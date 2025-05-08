from pwn import *

level1 = [42, 1]
while len(level1) <= 5:
    level1.append(level1[-1] + level1[-2])

v2 = [ord(c) for c in 'g"imya%non``zxI']
extra_vals = [-16, -104, 49, -44, -27, -80, 29, -97, -18, -76, -95, 105, -61]
v2.extend([(x + 256) % 256 for x in extra_vals])
l2 = ""
for i in range(14):
    upper = v2[i] & 0xF0
    lower = v2[i + 14] & 0x0F
    char_val = upper | lower
    l2 += chr(char_val)

random_values = [1804289383, 846930886, 1681692777, 1714636915, 1957747793]
random_values = [val & 0xF for val in random_values]
l3 = [(15 - r) & 0xF for r in random_values][::-1]
l3 = " ".join(map(str, l3))
print(l3)

elf = context.binary = ELF('./proveyourworth')
# p = process()
p = remote("chals.t.cyberthon25.ctf.sg", 31021)
print(p.recvuntil(b'=> '))
l1 = " ".join(map(str, level1[1: ]))
p.sendline(str(l1).encode() + l2.encode())

p.recvuntil(b'=> ')
p.sendline(l3.encode())

p.interactive()
