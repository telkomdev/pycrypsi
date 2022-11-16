import unittest
from pycrypsi import digest

class TestDigest(unittest.TestCase):
    key = 'abc$#128djdyAgbjau&YAnmcbagryt5x'
    invalidKey = '12345'

    def test_digest_md5(self):
        expected = '60e1bc04fa194a343b50ce67f4afcff8'

        data = 'wuriyanto'
        actual = digest.md5_hex(bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_digest_sha1(self):
        expected = 'afd2bd72af0c346a2ab14d50746835d3ccd1dd5f'

        data = 'wuriyanto'
        actual = digest.sha1_hex(bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_digest_sha256(self):
        expected = '7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87'

        data = 'wuriyanto'
        actual = digest.sha256_hex(bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_digest_sha384(self):
        expected = '2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1'

        data = 'wuriyanto'
        actual = digest.sha384_hex(bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_digest_sha512(self):
        expected = '5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206'

        data = 'wuriyanto'
        actual = digest.sha512_hex(bytes(data, 'utf-8'))
        self.assertEqual(expected, actual)
    
    def test_digest_sha512_multiple_data(self):
        expected = '54f477deede8965bfbafa3867dae445a1b6ce3cb5169f5f8239802b1a2c7a65afeb0dbdc66be756df48d1e60c717dc300c6fe81af359677c32f99f45d8ac8bee'

        data1 = 'wuriyanto'
        data2 = 'alex'
        data3 = 'bobby'
        actual = digest.sha512_hex(bytes(data1, 'utf-8'), bytes(data2, 'utf-8'), bytes(data3, 'utf-8'))
        self.assertEqual(expected, actual)