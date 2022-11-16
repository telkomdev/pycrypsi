import unittest
from pycrypsi import hmac

class TestHMAC(unittest.TestCase):
    key = 'abc$#128djdyAgbjau&YAnmcbagryt5x'
    invalidKey = '12345'

    def test_hmac_md5(self):
        expected = 'd213b2e973c1a5d704255518af6d073c'

        data = 'wuriyanto'
        actual = hmac.md5_hex(bytes(self.key, 'utf-8'), bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha1(self):
        expected = '69fa82ae1f1398e6e570a4780df908adad3998df'

        data = 'wuriyanto'
        actual = hmac.sha1_hex(bytes(self.key, 'utf-8'), bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha256(self):
        expected = '9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240'

        data = 'wuriyanto'
        actual = hmac.sha256_hex(bytes(self.key, 'utf-8'), bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha384(self):
        expected = '69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4'

        data = 'wuriyanto'
        actual = hmac.sha384_hex(bytes(self.key, 'utf-8'), bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha512(self):
        expected = '0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8'

        data = 'wuriyanto'
        actual = hmac.sha512_hex(bytes(self.key, 'utf-8'), bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha512_multiple_data(self):
        expected = 'db26189014cb4f63748313533d27b12248222f2ef0952af8d029b184f0870c14b0c7e9df7d4241de9f6a608c5eddb5828f93ea2e6e199d0f2085148676e855f8'

        data1 = 'wuriyanto'
        data2 = 'alex'
        data3 = 'bobby'
        actual = hmac.sha512_hex(bytes(self.key, 'utf-8'), bytes(data1, 'utf-8'), bytes(data2, 'utf-8'), bytes(data3, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_hmac_sha512_throw_error_with_invalid_key(self):
        expected = '0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8'

        data = 'wuriyanto'
        with self.assertRaises(Exception):
            actual = hmac.sha512_hex(bytes(self.invalidKey, 'utf-8'), bytes(data, 'utf-8'))