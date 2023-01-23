from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_AUTH_TAG_LENGTH = 16

AES_128_KEY_SIZE = 16
AES_192_KEY_SIZE = 24
AES_256_KEY_SIZE = 32

AES_CBC_MODE = 'cbc'
AES_CCM_MODE = 'ccm'
AES_OCB_MODE = 'ocb'
AES_GCM_MODE = 'gcm'

AES_128_CBC = 'aes-128-cbc'
AES_192_CBC = 'aes-192-cbc'
AES_256_CBC = 'aes-256-cbc'

AES_128_GCM = 'aes-128-gcm'
AES_192_GCM = 'aes-192-gcm'
AES_256_GCM = 'aes-256-gcm'

AES_128_CCM = 'aes-128-ccm'
AES_192_CCM = 'aes-192-ccm'
AES_256_CCM = 'aes-256-ccm'

AES_128_OCB = 'aes-128-ocb'
AES_192_OCB = 'aes-192-ocb'
AES_256_OCB = 'aes-256-ocb'

def __is_valid_aes_key(key: bytes) -> bool:
    key_len = len(key)
    aes_keys= [AES_128_KEY_SIZE, AES_192_KEY_SIZE, AES_256_KEY_SIZE]
    if key_len not in aes_keys: 
        return False
    return True

def __is_valid_aes_mode(mode: str) -> bool:
    aes_keys= [AES_CBC_MODE, AES_CCM_MODE, AES_OCB_MODE, AES_GCM_MODE]
    if mode not in aes_keys: 
        return False
    return True

def __get_meta_from_aes_alg(alg: str):
    alg_splited = alg.split('-')
    if len(alg_splited) < 3:
        raise Exception('invalid aes algorithm')
    
    key_len = int(alg_splited[1], base=10)
    iv_len = 12
    if alg_splited[2] == 'cbc':
        iv_len = 16
    
    return {
        'expected_key_len': int(key_len/8),
        'mode': alg_splited[2],
        'iv_len': iv_len
    }

def __encrypt(alg: str, key: bytes, plain_data: bytes) -> bytes:
    meta = __get_meta_from_aes_alg(alg)
    if len(key) != meta['expected_key_len']:
        raise Exception('invalid key size')

    if not __is_valid_aes_mode(meta['mode']):
        raise Exception('invalid mode')

    mode = AES.MODE_CCM
    if meta['mode'] == AES_OCB_MODE:
        mode = AES.MODE_OCB
    elif meta['mode'] == AES_GCM_MODE:
        mode = AES.MODE_GCM
    elif meta['mode'] == AES_CBC_MODE:
        mode = AES.MODE_CBC

    nonce = get_random_bytes(meta['iv_len'])
    
    all_data = b''
    supported_tags = [AES_CCM_MODE, AES_OCB_MODE, AES_GCM_MODE]
    
    if meta['mode'] in supported_tags:
        cipher = AES.new(key=key, mode=mode, nonce=nonce)
        cipher_data, tag = cipher.encrypt_and_digest(plain_data)
        all_data = nonce+cipher_data+tag
    else:
        cipher = AES.new(key=key, mode=mode, iv=nonce)
        if meta['mode'] == AES_CBC_MODE:
            plain_data = pad(plain_data, AES.block_size)
        cipher_data = cipher.encrypt(plain_data)
        all_data = cipher.iv+cipher_data
    return all_data

def __decrypt(alg: str, key: bytes, encrypted_data: str) -> bytes:
    meta = __get_meta_from_aes_alg(alg)
    if len(key) != meta['expected_key_len']:
        raise Exception('invalid key size')

    if not __is_valid_aes_mode(meta['mode']):
        raise Exception('invalid mode')

    mode = AES.MODE_CCM
    if meta['mode'] == AES_OCB_MODE:
        mode = AES.MODE_OCB
    elif meta['mode'] == AES_GCM_MODE:
        mode = AES.MODE_GCM
    elif meta['mode'] == AES_CBC_MODE:
        mode = AES.MODE_CBC

    buf = bytes.fromhex(encrypted_data)
    supported_tags = [AES_CCM_MODE, AES_OCB_MODE, AES_GCM_MODE]
    
    nonce = buf[0:meta['iv_len']]
    tag = b''
    plain_data = b''
    if meta['mode'] in supported_tags:
        s_from = len(buf) - DEFAULT_AUTH_TAG_LENGTH
        tag = buf[s_from:len(buf)]
        buf = buf[meta['iv_len']:s_from]
        cipher = AES.new(key=key, mode=mode, nonce=nonce)
        plain_data = cipher.decrypt_and_verify(buf, tag)
    else:
        cipher = AES.new(key=key, mode=mode, iv=nonce)
        buf = buf[meta['iv_len']:len(buf)]
        plain_data = cipher.decrypt(buf)
        if meta['mode'] == AES_CBC_MODE:
            plain_data = unpad(plain_data, AES.block_size)

    return plain_data

# cbc
def encrypt_with_aes128_cbc_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_128_CBC, key, plain_data).hex()

def encrypt_with_aes192_cbc_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_192_CBC, key, plain_data).hex()

def encrypt_with_aes256_cbc_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_256_CBC, key, plain_data).hex()

def decrypt_with_aes128_cbc_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_128_CBC, key, encrypted_data)

def decrypt_with_aes192_cbc_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_192_CBC, key, encrypted_data)

def decrypt_with_aes256_cbc_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_256_CBC, key, encrypted_data)

# gcm
def encrypt_with_aes128_gcm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_128_GCM, key, plain_data).hex()

def encrypt_with_aes192_gcm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_192_GCM, key, plain_data).hex()

def encrypt_with_aes256_gcm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_256_GCM, key, plain_data).hex()

def decrypt_with_aes128_gcm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_128_GCM, key, encrypted_data)

def decrypt_with_aes192_gcm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_192_GCM, key, encrypted_data)

def decrypt_with_aes256_gcm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_256_GCM, key, encrypted_data)

# ccm
def encrypt_with_aes128_ccm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_128_CCM, key, plain_data).hex()

def encrypt_with_aes192_ccm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_192_CCM, key, plain_data).hex()

def encrypt_with_aes256_ccm_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_256_CCM, key, plain_data).hex()

def decrypt_with_aes128_ccm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_128_CCM, key, encrypted_data)

def decrypt_with_aes192_ccm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_192_CCM, key, encrypted_data)

def decrypt_with_aes256_ccm_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_256_CCM, key, encrypted_data)

# ocb
def encrypt_with_aes128_ocb_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_128_OCB, key, plain_data).hex()

def encrypt_with_aes192_ocb_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_192_OCB, key, plain_data).hex()

def encrypt_with_aes256_ocb_hex(key: bytes, plain_data: bytes) -> str:
    return __encrypt(AES_256_OCB, key, plain_data).hex()

def decrypt_with_aes128_ocb_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_128_OCB, key, encrypted_data)

def decrypt_with_aes192_ocb_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_192_OCB, key, encrypted_data)

def decrypt_with_aes256_ocb_hex(key: bytes, encrypted_data: str) -> bytes:
    return __decrypt(AES_256_OCB, key, encrypted_data)