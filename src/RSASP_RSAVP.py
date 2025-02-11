import base64
from hashlib import sha3_256

class RSASignature:
    @staticmethod
    def sign(message, private_key):
        """Sign a message using RSA-SHA3"""
        hashed = sha3_256(message).digest()
        m = int.from_bytes(hashed, byteorder='big')
        d, n = private_key
        s = pow(m, d, n)
        return base64.b64encode(s.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))

    @staticmethod
    def verify(message, signature, public_key):
        """Verify an RSA-SHA3 signature"""
        hashed = sha3_256(message).digest()
        m = int.from_bytes(hashed, byteorder='big')
        signature = int.from_bytes(base64.b64decode(signature), byteorder='big')
        e, n = public_key
        s = pow(signature, e, n)
        return m == s
