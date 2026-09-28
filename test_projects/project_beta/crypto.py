from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

KEY = b"8bytekey"


def encrypt(data):
    cipher = DES.new(KEY, DES.MODE_ECB)
    return cipher.encrypt(pad(data, 8))


def decrypt(blob):
    cipher = DES.new(KEY, DES.MODE_ECB)
    return cipher.decrypt(blob)
