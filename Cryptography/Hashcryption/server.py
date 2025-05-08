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

def banner():
    write("  _    _           _      _____                  _   _\n")
    write(" | |  | |         | |    / ____|                | | (_)\n")
    write(" | |__| | __ _ ___| |__ | |     _ __ _   _ _ __ | |_ _  ___  _ __\n")
    write(" |  __  |/ _` / __| '_ \\| |    | '__| | | | '_ \\| __| |/ _ \\| '_ \\\n")
    write(" | |  | | (_| \\__ | | | | |____| |  | |_| | |_) | |_| | (_) | | | |\n")
    write(" |_|  |_|\\__,_|___|_| |_|\\_____|_|   \\__, | .__/ \\__|_|\\___/|_| |_|\n")
    write("                                      __/ | |\n")
    write("                                     |___/|_|\n")
    write("\n");

banner()

data = read('[+] Data: ')
write('[+] Encrypted:\n')
write('----------------------------- START -------------------------------\n')
write(encrypt(data, KEY))
write('\n------------------------------ END --------------------------------')
