## pycrypsi (Python Crypto Utility)

Custom crypto utility that wraps the `pycryptodome` module to make life easier

[![pycrypsi CI](https://github.com/telkomdev/pycrypsi/actions/workflows/ci.yml/badge.svg)](https://github.com/telkomdev/pycrypsi/actions/workflows/ci.yml)

### pycrypsi is compatible with each other with the following libraries
- NodeJs https://github.com/telkomdev/crypsi
- Golang https://github.com/telkomdev/go-crypsi
- C# (.NET) https://github.com/telkomdev/NetCrypsi
- Java/JVM https://github.com/telkomdev/jcrypsi
- Javascript (React and Browser) https://github.com/telkomdev/crypsi.js

### Features
- Asymmetric encryption with RSA
- Generate RSA private and public key
- Digital Signature with RSA private and public key using PSS
- Symmetric encryption with AES
- Message authentication code with HMAC
- Generate Hash with Common DIGEST Algorithm

### Usage

Generate RSA Private and Public key
```python
from pycrypsi import (
    rsa
)

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    private_key, public_key, private_key_b64, public_key_b64 = rsa.generate_key_pairs(rsa.KEY_SIZE_2KB)
    print(private_key.decode())
    print(public_key.decode())
    print()
    print(private_key_b64.decode())
    print()
    print(public_key_b64.decode())

    with open('private.key', 'wb') as private_key_writer:
        private_key_writer.write(private_key)
    
    with open('public.key', 'wb') as public_key_writer:
        public_key_writer.write(public_key)

if __name__ == "__main__":
    main()
```

Generate `HASH` with common `Digest Algorithm`
```python
from pycrypsi import (
    digest
)

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    print(digest.md5_hex(b'wuriyanto'))
    print(digest.sha1_hex(b'wuriyanto', b'alex'))
    print(digest.sha1_hex(b'wuriyanto', b'alex', b'bobby'))

    print(digest.sha256_hex(b'wuriyanto'))
    print(digest.sha384_hex(b'wuriyanto'))
    print(digest.sha512_hex(b'wuriyanto'))

    data = 'wuriyanto'
    print(digest.sha256_hex(bytes(data, 'utf-8')))

    # get Hash value from file

    with open(os.path.join(BASE_DIR, 'tests', 'testdata', 'gopher.png'), 'rb') as input_file:
        hash_val = digest.sha256_hex(input_file.read())
        print(hash_val)
        
if __name__ == "__main__":
    main()
```

Data and File Encryption with AES
```python
from pycrypsi import (
    aes
)

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    key256 = "abc$#128djdyAgbjau&YAnmcbagryt5x"

    data = 'wuriyanto'

    res_data_encrypted = aes.encrypt_with_aes256_cbc_hex(bytes(key256, 'utf-8'), bytes(data, 'utf-8'))
    print(res_data_encrypted)

    res_data_decrypted = aes.decrypt_with_aes256_cbc_hex(bytes(key256, 'utf-8'), res_data_encrypted)
    print(res_data_decrypted.decode())

    # encrypt and decrypt file
    with open(os.path.join(BASE_DIR, 'tests', 'testdata', 'gopher.png'), 'rb') as input_file:
        encrypted_file_data = aes.encrypt_with_aes256_cbc_hex(bytes(key256, 'utf-8'), input_file.read())
        with open('out.bin', 'wb') as out_file:
            out_file.write(encrypted_file_data.encode())
    
    with open('out.bin', 'rb') as input_file:
        # print(input_file.read().decode())
        decrypted_file_data = aes.decrypt_with_aes256_cbc_hex(bytes(key256, 'utf-8'), input_file.read().decode())
        with open('out.png', 'wb') as out_file:
            out_file.write(decrypted_file_data)
if __name__ == "__main__":
    main()
```

Generate `HASH` with `HMAC (Hash-Based Message Authentication Codes)`
```python
from pycrypsi import (
    hmac
)

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    key = 'abc$#128djdyAgbjau&YAnmcbagryt5x'
    print(hmac.md5_hex(bytes(key, 'utf-8'), b'wuriyanto'))
    print(hmac.sha1_hex(bytes(key, 'utf-8'), b'wuriyanto', b'alex'))
    print(hmac.sha1_hex(bytes(key, 'utf-8'), b'wuriyanto', b'alex', b'bobby'))

    print(hmac.sha256_hex(bytes(key, 'utf-8'), b'wuriyanto'))
    print(hmac.sha384_hex(bytes(key, 'utf-8'), b'wuriyanto'))
    print(hmac.sha512_hex(bytes(key, 'utf-8'), b'wuriyanto'))

    data = 'wuriyanto'
    print(hmac.sha256_hex(bytes(key, 'utf-8'), bytes(data, 'utf-8')))

    # get Hash value from file

    with open(os.path.join(BASE_DIR, 'tests', 'testdata', 'gopher.png'), 'rb') as input_file:
        hash_val = hmac.sha256_hex(bytes(key, 'utf-8'), input_file.read())
        print(hash_val)
        
if __name__ == "__main__":
    main()
```