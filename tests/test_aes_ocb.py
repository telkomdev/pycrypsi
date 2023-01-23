import unittest
from pycrypsi import aes

class TestAESOcb(unittest.TestCase):

    # ocb
    def test_encrypt_decrypt_aes128_ocb(self):
        key = bytes.fromhex('6368616e676520746869732070617373')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_with_aes128_ocb_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_with_aes128_ocb_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes192_ocb(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_with_aes192_ocb_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_with_aes192_ocb_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes256_ocb(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d403534727475746965')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_with_aes256_ocb_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_with_aes256_ocb_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)
    
    def test_encrypt_decrypt_aes128_ocb_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_with_aes128_ocb_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes192_ocb_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_with_aes192_ocb_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes256_ocb_throw_error_with_invalid_key(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_with_aes256_ocb_hex(key, bytes(data, 'utf-8'))