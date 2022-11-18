import os
import unittest
from pycrypsi import aes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class TestAESGcm(unittest.TestCase):

    # gcm
    def test_encrypt_decrypt_aes128_gcm(self):
        key = bytes.fromhex('6368616e676520746869732070617373')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes128_gcm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes128_gcm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes192_gcm(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes192_gcm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes192_gcm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes256_gcm(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d403534727475746965')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes256_gcm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes256_gcm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)
    
    def test_encrypt_decrypt_aes128_gcm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes128_gcm_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes192_gcm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes192_gcm_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes256_gcm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes256_gcm_hex(key, bytes(data, 'utf-8'))
    
    def test_file_with_decrypt_aes256_gcm(self):
        key = bytes.fromhex('6368616e6765207468697320706173736368616e676520746869732070617373')
        
        actual_file_path = os.path.join(BASE_DIR, 'testdata/gopher.png')
        encrypted_file_path = os.path.join(BASE_DIR, 'testdata/encrypted_file.bin')

        with open(encrypted_file_path, 'rb') as input_file:
            decrypted_file_data = aes.decrypt_aes256_gcm_hex(key, input_file.read().decode())
            with open(actual_file_path, 'rb') as actual_file:
                self.assertEqual(decrypted_file_data, actual_file.read())