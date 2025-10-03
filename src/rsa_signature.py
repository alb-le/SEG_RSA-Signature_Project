import base64
import traceback
from hashlib import sha1,sha224,sha256
from src.data_conversion import i2osp,os2ip
from src.utils import b64


class RSASignature:
    def __init__(self):
        """
        Initialize RSASignature with specified hash algorithm.
        hash_algorithm: the hash function to be used (sha1, sha224, sha256)
        """
        self.hash_func = sha256

    def sign(self, M, private_key): # M = message Octet-String primitive
        """Sign a message using RSA with the specified hash algorithm"""
        hashed = self.hash_func(M).digest()
        m = os2ip(hashed) # Integer primitive
        d, n = private_key
        s = pow(m, d, n)
        s_len = (n.bit_length() + 7) // 8
        signature = i2osp(s, s_len)
        return b64.encode(signature)

    def verify(self, M, signature, public_key):
        """Verify an RSA signature with the specified hash algorithm"""
        try:
            hashed = self.hash_func(M).digest()
            m = os2ip(hashed)
            decode_signature = b64.decode(signature)
            s = os2ip(decode_signature)
            e, n = public_key
            verified_m = pow(s, e, n)
            return m == verified_m
        except Exception as e:
            print(f"An error occurred during verification: {e}")
            traceback.print_exc()
            return False
