import unittest
from src.rsa_core import RSACore, OAEP, RSASignature


class TestRSA(unittest.TestCase):

    def setUp(self):
        self.signature_service = RSASignature
        self.rsa_core = RSACore()
        self.pub_key, self.priv_key = self.rsa_core.generate_keypair()

    def test_keypair_generation(self):
        e, n = self.pub_key
        d, n2 = self.priv_key
        self.assertEqual(n, n2)
        self.assertTrue(self.pub_key)
        self.assertTrue(self.priv_key)

    def test_oaep_padding(self):
        oaep = OAEP(1024)
        message = b"Hello, RSA with OAEP!"
        padded = oaep.pad(message)
        unpadded = oaep.unpad(padded)
        self.assertEqual(message, unpadded)

    def test_sign_and_verify(self):
        message = b"Test message for RSA signing"
        signature = self.signature_service.sign(message, self.priv_key)
        is_valid = self.signature_service.verify(message, signature, self.pub_key)
        self.assertTrue(is_valid)


if __name__ == '__main__':
    unittest.main()
