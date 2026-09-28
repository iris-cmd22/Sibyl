import hashlib


def hash_password(password):
    digest = hashlib.md5(password.encode())
    return digest.hexdigest()


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()


def checksum(path):
    with open(path, "rb") as handle:
        return hashlib.new("md4", handle.read()).hexdigest()
