from Crypto.Hash import MD5, SHA1, SHA256, SHA384, SHA512, HMAC

def __digest(digestmod, key: bytes, *datas) -> bytes:
    if len(key) < 32:
        raise Exception('minimum hmac key length must be greater or equal to 32')

    hmac = HMAC.new(key, digestmod=digestmod)
    for data in datas:
        hmac.update(data)
    return hmac.digest()

def md5_hex(key: bytes, *datas) -> str:
    return __digest(MD5, key, *datas).hex()

def sha1_hex(key: bytes, *datas) -> str:
    return __digest(SHA1, key, *datas).hex()

def sha256_hex(key: bytes, *datas) -> str:
    return __digest(SHA256, key, *datas).hex()

def sha384_hex(key: bytes, *datas) -> str:
    return __digest(SHA384, key, *datas).hex()

def sha512_hex(key: bytes, *datas) -> str:
    return __digest(SHA512, key, *datas).hex()