with open('flag.txt.encrypted', 'rb') as fp:
    data = fp.read()

key = []
s = "Here is the decrypted flag: "
for i in range(24):
    key.append(ord(s[i]) ^ data[i])

pt = ""
for i in range(len(data)):
    pt += chr(key[i % len(key)] ^ data[i])
print(pt)