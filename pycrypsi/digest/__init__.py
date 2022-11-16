from Crypto.Hash import MD5, SHA1, SHA256, SHA384, SHA512

def __digest(hash, *datas) -> bytes:
    for data in datas:
        hash.update(data)
    return hash.digest()

def md5_hex(*datas) -> str:
    hash = MD5.new()
    return __digest(hash, *datas).hex()

def sha1_hex(*datas) -> str:
    hash = SHA1.new()
    return __digest(hash, *datas).hex()

def sha256_hex(*datas) -> str:
    hash = SHA256.new()
    return __digest(hash, *datas).hex()

def sha384_hex(*datas) -> str:
    hash = SHA384.new()
    return __digest(hash, *datas).hex()

def sha512_hex(*datas) -> str:
    hash = SHA512.new()
    return __digest(hash, *datas).hex()