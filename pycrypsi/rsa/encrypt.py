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
encrypt with OAEP
returns bytes
'''
def __encrypt_with_oap(public_key, hash_algo, plain_data: bytes) -> bytes:
    if not isinstance(public_key, RSA.RsaKey):
        public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=hash_algo)
    cipher_data = cipher.encrypt(plain_data)
    return cipher_data

'''
encrypt with OAEP md5
returns bytes
'''
def encrypt_with_oap_md5(public_key, plain_data: bytes) -> bytes:
    return __encrypt_with_oap(public_key, MD5, plain_data)

'''
encrypt with OAEP sha1
returns bytes
'''
def encrypt_with_oap_sha1(public_key, plain_data: bytes) -> bytes:
    return __encrypt_with_oap(public_key, SHA1, plain_data)

'''
encrypt with OAEP sha256
returns bytes
'''
def encrypt_with_oap_sha256(public_key, plain_data: bytes) -> bytes:
    return __encrypt_with_oap(public_key, SHA256, plain_data)

'''
encrypt with OAEP sha384
returns bytes
'''
def encrypt_with_oap_sha384(public_key, plain_data: bytes) -> bytes:
    return __encrypt_with_oap(public_key, SHA384, plain_data)

'''
encrypt with OAEP sha512
returns bytes
'''
def encrypt_with_oap_sha512(public_key, plain_data: bytes) -> bytes:
    return __encrypt_with_oap(public_key, SHA512, plain_data)