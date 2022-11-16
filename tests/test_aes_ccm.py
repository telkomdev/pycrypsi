import unittest
from pycrypsi import aes

class TestAESCcm(unittest.TestCase):

    # ccm
    def test_encrypt_decrypt_aes128_ccm(self):
        key = bytes.fromhex('6368616e676520746869732070617373')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes128_ccm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes128_ccm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes192_ccm(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes192_ccm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes192_ccm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)

    def test_encrypt_decrypt_aes256_ccm(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d403534727475746965')
        data = 'exampleplaintext'

        result_encrypt = aes.encrypt_aes256_ccm_hex(key, bytes(data, 'utf-8'))
        self.assertIsNotNone(result_encrypt)

        result_decrypt = aes.decrypt_aes256_ccm_hex(key, result_encrypt)

        self.assertEqual(bytes(data, 'utf-8'), result_decrypt)
    
    def test_encrypt_decrypt_aes128_ccm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes128_ccm_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes192_ccm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('6368616e6765207468697320706173')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes192_ccm_hex(key, bytes(data, 'utf-8'))
    
    def test_encrypt_decrypt_aes256_ccm_throw_error_with_invalid_key(self):
        key = bytes.fromhex('48656c6c6f75656a656e6777656b67756538232461616d40')
        data = 'exampleplaintext'

        with self.assertRaises(Exception):
            result_encrypt = aes.encrypt_aes256_ccm_hex(key, bytes(data, 'utf-8'))