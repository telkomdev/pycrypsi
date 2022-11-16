import base64
from Crypto.PublicKey import RSA

from .decrypt import (
    decrypt_with_oap_md5,
    decrypt_with_oap_sha1,
    decrypt_with_oap_sha256,
    decrypt_with_oap_sha384,
    decrypt_with_oap_sha512,
)

from .encrypt import (
    encrypt_with_oap_md5,
    encrypt_with_oap_sha1,
    encrypt_with_oap_sha256,
    encrypt_with_oap_sha384,
    encrypt_with_oap_sha512,
)

# 1024
KEY_SIZE_1KB = 1 << 10

# 2048
KEY_SIZE_2KB = 1 << 11

# 4096
KEY_SIZE_4KB = 1 << 12

def __is_valid_rsa_key_size(key_size: int) -> bool:
    sizes = [KEY_SIZE_1KB, KEY_SIZE_2KB, KEY_SIZE_4KB]
    if key_size not in sizes: 
        return False
    return True

'''
generate_key_pairs will generate pair of RSA private key and public key
returns (private_key, public_key)
'''
def generate_key_pairs(key_size: int):
    if not __is_valid_rsa_key_size(key_size=key_size):
        raise Exception('key size should between 1024 , 2048 or 4096')
    rsa_key_pair = RSA.generate(key_size)
    private_key = rsa_key_pair.export_key('PEM', pkcs=8)
    public_key = rsa_key_pair.public_key().export_key('PEM')

    private_key_base64 = base64.b64encode(private_key)
    public_key_base64 = base64.b64encode(public_key)

    return (private_key, public_key, private_key_base64, public_key_base64)

'''
load_key will load RSA private or public key
'''
def load_key(key):
    return RSA.importKey(key)

'''
load_key_from_base64 will load RSA private or public key from base64 encoded key
'''
def load_key_from_base64(base64_key):
    base64_decoded = base64.b64decode(base64_key)
    return load_key(base64_decoded)