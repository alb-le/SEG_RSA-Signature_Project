import random
import os
import base64
from hashlib import sha3_256
import math


class RSACore:
    def __init__(self, bits=1024, public_exponent=65537):
        self.bits = bits
        self.e = public_exponent  # Commonly used public exponent

    #
    def generate_prime_candidate(self):  # Generate a random prime candidate with specified bit length
        # Generate random odd integer of specified bits
        candidate = random.getrandbits(self.bits)
        candidate |= (1 << self.bits - 1) | 1  # Set MSB and LSB to 1
        return candidate

    def miller_rabin_test(self, n, k=128):
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = (x * x) % n
                if x == 1:
                    return False
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime_number(self):
        while True:
            prime_candidate = self.generate_prime_candidate()
            if self.miller_rabin_test(prime_candidate):
                return prime_candidate

    def generate_keypair(self):
        """Generate RSA public and private key pair"""
        print("Generating p...")
        p = self.generate_prime_number()
        print("Generating q...")
        q = self.generate_prime_number()

        n = p * q
        phi = (p - 1) * (q - 1)

        # Calculate private key
        d = pow(self.e, -1, phi)

        return (self.e, n), (d, n)

    def rsaep(self, public_key, m):
        """RSAEP implementation (Section 5.1.1)"""
        # Unpack the public key tuple into modulus (n) and public exponent (e)
        n, e = public_key
        # Check if message representative m is within valid range
        # m must be non-negative (>= 0) and less than modulus n
        if not (0 <= m < n):
            raise ValueError("message representative out of range")
        # Perform RSA encryption operation:
        # c = m^e mod n
        # pow(m, e, n) is Python's built-in modular exponentiation
        # This is more efficient than (m ** e) % n
        return pow(m, e, n)

    def rsadp(self, private_key, c):
        """RSADP implementation (Section 5.1.2)"""
        n, d = private_key

        if not (0 <= c < n):
            raise ValueError("ciphertext representative out of range")

        return pow(c, d, n)


class OAEP:
    def __init__(self, n_len, rsa_core):
        """Initialize OAEP parameters"""
        self.hLen = 32  # SHA3-256 output length
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
            C = counter.to_bytes(4, byteorder='big')
            result += sha3_256(seed + C).digest()
            counter += 1

        return result[:length]

    def encode(self, message, L=None):
        """EME-OAEP encoding (Section 7.1.1)"""
        L = L if L is not None else self.L

        mLen = len(message)
        if len(L) > (2 ** 61 - 1):
            raise ValueError("label too long")

        # Calculate maximum message length
        max_message_len = self.n_len - 2 * self.hLen - 2

        if mLen > max_message_len:
            # Calculate how many characters are beyond the limit
            excess_chars = mLen - max_message_len
            raise ValueError(
                f"Message too long. It exceeds the limit by {excess_chars} characters. "
                f"Please remove at least {excess_chars} characters to fit within the limit."
            )

        lHash = sha3_256(L).digest()
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

    def decode(self, EM, L=None):
        """EME-OAEP decoding (Section 7.1.2)"""
        L = L if L is not None else self.L

        if len(L) > (2 ** 61 - 1):
            raise ValueError("decryption error")
        if len(EM) != self.n_len:
            raise ValueError("decryption error")
        if self.n_len < 2 * self.hLen + 2:
            raise ValueError("decryption error")

        lHash = sha3_256(L).digest()
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

    def encrypt_with_oaep(self, message, public_key, label=None):
        """RSAES-OAEP-ENCRYPT implementation using RSAEP primitive"""
        try:
            EM = self.encode(message, label)
            m = int.from_bytes(EM, byteorder='big')
            # Use RSAEP primitive
            c = self.rsa_core.rsaep(public_key, m)
            return c.to_bytes(self.n_len, byteorder='big')
        except ValueError as e:
            raise ValueError("encryption error: " + str(e)) from e

    def decrypt_with_oaep(self, ciphertext, private_key, label=None):
        """RSAES-OAEP-DECRYPT implementation"""
        try:
            if len(ciphertext) != self.n_len:
                raise ValueError("decryption error")

            c = int.from_bytes(ciphertext, byteorder='big')
            # Use RSADP primitive
            m = self.rsa_core.rsadp(private_key, c)

            EM = m.to_bytes(self.n_len, byteorder='big')
            return self.decode(EM, label)
        except Exception as e:
            raise ValueError("decryption error") from e


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


def main():
    """Demonstration of RSA encryption, decryption, signing, and verification"""
    try:
        # Key generation
        rsa = RSACore(bits=2048)
        pub_key, priv_key = rsa.generate_keypair()
        signing_pub_key, signing_priv_key = rsa.generate_keypair()

        print(f"public key:{pub_key}")
        print(f"private key:{priv_key}")
        # Original message
        message = b"Optimized RSA"
        label = b"optional"

        # Assinatura da mensagem
        signature = RSASignature.sign(message, signing_priv_key)

        # Concatenar mensagem e assinatura
        combined_message = message + base64.b64decode(signature)

        # Calculate n_len from the public key
        n_len = (pub_key[1].bit_length() + 7) // 8  # pub_key[1] is the modulus n

        # Calculate maximum message length
        hLen = 32  # SHA3-256 output length
        max_message_len = n_len - 2 * hLen - 2

        # Check if combined_message is too long
        if len(combined_message) > max_message_len:
            excess_chars = len(combined_message) - max_message_len
            raise ValueError(
                f"Combined message (message + signature) too long. "
                f"It exceeds the limit by {excess_chars} characters. "
                f"Please reduce the message length or use a larger RSA key."
            )

        # Criptografia com OAEP
        oaep = OAEP(n_len, rsa_core=rsa)
        encrypted = oaep.encrypt_with_oaep(combined_message, pub_key, label)

        print("Ciphertext:", ciphertext.hex())

        # Decriptação com OAEP
        decrypted_combined = oaep.decrypt_with_oaep(encrypted, priv_key, label)

        # Separar mensagem e assinatura
        decrypted_message = decrypted_combined[:len(message)]
        decrypted_signature = base64.b64encode(decrypted_combined[len(message):])

        # Verificação da assinatura
        is_valid = RSASignature.verify(decrypted_message, decrypted_signature, signing_pub_key)

        # Output results
        print(f"Original message: {message}")
        print(f"Decrypted message: {decrypted_message}")
        print(f"Signature valid: {is_valid}")

        assert message == decrypted_message, "Decryption failed"
        assert is_valid, "Signature verification failed"
        print("Success! RSA operations completed correctly.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()
