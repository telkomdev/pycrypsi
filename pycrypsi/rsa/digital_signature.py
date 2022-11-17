from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto import Random
from Crypto.Hash import (
    MD5, 
    SHA1, 
    SHA256, 
    SHA384, 
    SHA512,
)

def __sign_with_pss(private_key, hash_algo, data: bytes) -> bytes:
    if not isinstance(private_key, RSA.RsaKey):
        private_key = RSA.importKey(private_key)
    
    hash = hash_algo.new(data)
    signature = pss.new(private_key).sign(hash)
    return signature

def __verify_signature_with_pss(public_key, hash_algo, signature: bytes, data: bytes) -> bool:
    if not isinstance(public_key, RSA.RsaKey):
        public_key = RSA.importKey(public_key)
    
    hash = hash_algo.new(data)
    verifier = pss.new(public_key)
    try:
        verifier.verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# sign 
def sign_with_pss_md5(private_key, data: bytes) -> bytes:
    return __sign_with_pss(private_key, MD5, data)

def sign_with_pss_sha1(private_key, data: bytes) -> bytes:
    return __sign_with_pss(private_key, SHA1, data)

def sign_with_pss_sha256(private_key, data: bytes) -> bytes:
    return __sign_with_pss(private_key, SHA256, data)

def sign_with_pss_sha384(private_key, data: bytes) -> bytes:
    return __sign_with_pss(private_key, SHA384, data)

def sign_with_pss_sha512(private_key, data: bytes) -> bytes:
    return __sign_with_pss(private_key, SHA512, data)

# verify
def verify_signature_with_pss_md5(public_key, signature: bytes, data: bytes) -> bool:
    return __verify_signature_with_pss(public_key, MD5, signature, data)

def verify_signature_with_pss_sha1(public_key, signature: bytes, data: bytes) -> bool:
    return __verify_signature_with_pss(public_key, SHA1, signature, data)

def verify_signature_with_pss_sha256(public_key, signature: bytes, data: bytes) -> bool:
    return __verify_signature_with_pss(public_key, SHA256, signature, data)

def verify_signature_with_pss_sha384(public_key, signature: bytes, data: bytes) -> bool:
    return __verify_signature_with_pss(public_key, SHA384, signature, data)

def verify_signature_with_pss_sha512(public_key, signature: bytes, data: bytes) -> bool:
    return __verify_signature_with_pss(public_key, SHA512, signature, data)