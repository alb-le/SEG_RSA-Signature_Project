import base64
from hashlib import sha1,sha224,sha256
from data_conversion import i2osp,os2ip

class RSASignature:
    def __init__(self):
        """
        Initialize RSASignature with specified hash algorithm.
        hash_algorithm: the hash function to be used (sha1, sha224, sha256)
        """
        self.hash_func = sha256

    def sign(self, M, private_key): # M = message Octet-String primitive
        """Sign a message using RSA with the specified hash algorithm"""
        try:
            hashed = self.hash_func(M).digest()
            m = os2ip(hashed) # Integer primitive 
            d, n = private_key
            s = pow(m, d, n)
            s_len = (n.bit_length() + 7) // 8
            signature = i2osp(s, s_len)
            return base64.b64encode(signature)
        except Exception as e:
            print(f"An error occurred during signing: {e}")
            return None

    def verify(self, M, signature, public_key, hash_algorithm='sha1'):
        """Verify an RSA signature with the specified hash algorithm"""
        if hash_algorithm:
            self.hash_func = self._select_hash_function(hash_algorithm)

        try:
            hashed = self.hash_func(M).digest()
            m = os2ip(hashed)
            decode_signature = base64.b64decode(signature)
            s = os2ip(decode_signature)
            e, n = public_key
            verified_m = pow(s, e, n)
            return m == verified_m
        except Exception as e:
            print(f"An error occurred during verification: {e}")
            return False
