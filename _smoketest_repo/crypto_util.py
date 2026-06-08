import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()       # weak hash (CWE-328)


def legacy_digest(data: bytes) -> str:
    h = hashlib.new("sha1")                     # weak algo via constant arg
    h.update(data)
    return h.hexdigest()
