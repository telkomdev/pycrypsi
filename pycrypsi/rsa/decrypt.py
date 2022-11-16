from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import (
    MD5, 
    SHA1, 
    SHA256, 
    SHA384, 
    SHA512,
)

'''
decrypt with OAEP
returns bytes
'''
def __decrypt_with_oap(private_key, hash_algo, encrypted_data: bytes) -> bytes:
    if not isinstance(private_key, RSA.RsaKey):
        private_key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=hash_algo)
    plain_data = cipher.decrypt(encrypted_data)
    return plain_data

'''
decrypt with OAEP md5
returns bytes
'''
def decrypt_with_oap_md5(private_key, encrypted_data: bytes) -> bytes:
    return __decrypt_with_oap(private_key, MD5, encrypted_data)

'''
decrypt with OAEP sha1
returns bytes
'''
def decrypt_with_oap_sha1(private_key, encrypted_data: bytes) -> bytes:
    return __decrypt_with_oap(private_key, SHA1, encrypted_data)

'''
decrypt with OAEP sha256
returns bytes
'''
def decrypt_with_oap_sha256(private_key, encrypted_data: bytes) -> bytes:
    return __decrypt_with_oap(private_key, SHA256, encrypted_data)

'''
decrypt with OAEP sha384
returns bytes
'''
def decrypt_with_oap_sha384(private_key, encrypted_data: bytes) -> bytes:
    return __decrypt_with_oap(private_key, SHA384, encrypted_data)

'''
decrypt with OAEP sha512
returns bytes
'''
def decrypt_with_oap_sha512(private_key, encrypted_data: bytes) -> bytes:
    return __decrypt_with_oap(private_key, SHA512, encrypted_data)