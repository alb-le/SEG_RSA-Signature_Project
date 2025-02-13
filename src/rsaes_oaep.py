import os
from hashlib import sha256
from data_conversion import i2osp, os2ip


class OAEP:  # OAEP Padding
    def __init__(self, n_len, rsa_core):
        """Initialize OAEP parameters
        n_len: length in octets of the RSA modulus n
        rsa_core: instance of the RSACore class
        hash_algorithm: the hash function to be used (sha1, sha224, sha256)
        """
        self.hash_func = sha256
        self.hLen = 32
        self.n_len = n_len  # Size of RSA modulus in bytes
        self.L = b""  # Default empty label
        self.rsa_core = rsa_core

    def _mgf1(self, seed, length):
        """Mask Generation Function based on SHA3-256"""
        if length > (2 ** 32) * self.hLen:
            raise ValueError("Mask too long")

        result = b''
        counter = 0

        while len(result) < length:
            C = i2osp(counter, 4)
            result += self.hash_func(seed + C).digest()
            counter += 1

        return result[:length]

    def encode(self, message: bytes, L=b""):
        """EME-OAEP encoding (Section 7.1.1)
        message (M): an octet string to be encoded
        L: optional label, an octet string
        Return encoded message (EM), an octet string
        """
        mLen = len(message)

        lHash = self.hash_func(L).digest()

        PS = b'\x00' * (self.n_len - mLen - 2 * self.hLen - 2)
        # Create data block
        DB = lHash + PS + b'\x01' + message

        # Generate random seed
        seed = os.urandom(self.hLen)

        # Generate masks
        dbMask = self._mgf1(seed, self.n_len - self.hLen - 1)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))

        seedMask = self._mgf1(maskedDB, self.hLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))

        # Concatenate everything
        return b'\x00' + maskedSeed + maskedDB

    def decode(self, EM, L=b""):
        """EME-OAEP decoding (Section 7.1.2)
        EM: encoded message, an octet string
        L: optional label, an octet string
        Return decoded message (M), an octet string"""

        lHash = self.hash_func(L).digest()
        Y = EM[0]
        maskedSeed = EM[1:self.hLen + 1]
        maskedDB = EM[self.hLen + 1:]

        # Recover seed
        seedMask = self._mgf1(maskedDB, self.hLen)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))

        # Recover data block
        dbMask = self._mgf1(seed, self.n_len - self.hLen - 1)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))

        lHash_prime = DB[:self.hLen]
        if not self._constant_time_compare(lHash, lHash_prime):
            raise ValueError("decryption error")

        # Find message boundary
        i = self.hLen
        while i < len(DB):
            if DB[i] == 0x01:
                break
            elif DB[i] != 0x00:
                raise ValueError("decryption error")
            i += 1

        if i == len(DB) or Y != 0:
            raise ValueError("decryption error")

        return DB[i + 1:]

    def _constant_time_compare(self, a, b):
        """Constant-time comparison of two strings"""
        if len(a) != len(b):
            return False
        return sum(x != y for x, y in zip(a, b)) == 0

    def rsaes_oaep_encrypt(self, public_key, message, label=b""):
        """
        RSAES-OAEP-ENCRYPT operation.
        public_key: (n, e) tuple
        message (M): an octet string to be encrypted
        label (L): optional label, an octet string
        Return ciphertext (C), an octet string
        """
        # Length checking
        L = label
        mLen = len(message)
        if len(L) > (2 ** 61 - 1):
            raise ValueError("label too long")

        k = self.n_len
        if mLen > k - 2 * self.hLen - 2:
            raise ValueError("message too long")

        # EME-OAEP encoding
        EM = self.encode(message, L)

        # Convert EM to an integer message representative m
        m = os2ip(EM)

        # Apply the RSAEP encryption primitive
        c = self.rsa_core.rsaep(public_key, m)

        # Convert the ciphertext representative c to a ciphertext C
        C = i2osp(c, k)

        return C

    def rsaes_oaep_decrypt(self, private_key, ciphertext, label=b""):
        """
        RSAES-OAEP-DECRYPT operation.
        private_key: (n, d) tuple
        ciphertext (C): an octet string to be decrypted
        label (L): optional label, an octet string
        Return decrypted message (M), an octet string
        """
        L = label

        k = self.n_len
        if len(L) > (2 ** 61 - 1):
            raise ValueError("decryption error")
        if len(ciphertext) != k:
            raise ValueError("decryption error")
        if k < 2 * self.hLen + 2:
            raise ValueError("decryption error")

        # Convert the ciphertext C to an integer ciphertext representative c
        c = os2ip(ciphertext)

        # Apply the RSADP decryption primitive
        m = self.rsa_core.rsadp(private_key, c)

        # Convert the message representative m to an encoded message EM
        EM = i2osp(m, k)

        # EME-OAEP decoding
        try:
            message = self.decode(EM, L)
        except ValueError:
            raise ValueError("Descryption error")

        return message
