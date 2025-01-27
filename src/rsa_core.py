import random
import os
import base64
from hashlib import sha3_256
import math

class RSACore:
    def __init__(self):
        self.bits = 1024
        self.e = 65537  # Commonly used public exponent

    def generate_prime_candidate(self, bits):
        # Generate random odd integer of specified bits
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
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
            a = random.randrange(2, n-2)
            x = pow(a, d, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(r-1):
                x = (x * x) % n
                if x == 1:
                    return False
                if x == n-1:
                    break
            else:
                return False
        return True

    def generate_prime_number(self):
        while True:
            prime_candidate = self.generate_prime_candidate(self.bits)
            if self.miller_rabin_test(prime_candidate):
                return prime_candidate

    def generate_keypair(self):
        print("Generating p...")
        p = self.generate_prime_number()
        print("Generating q...")
        q = self.generate_prime_number()
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Calculate private key
        d = pow(self.e, -1, phi)
        
        return (self.e, n), (d, n)

    def encrypt(self, message, public_key):
        """Encrypt a message using RSA-OAEP"""
        e, n = public_key
        # OAEP stands for Optimal Asymmetric Encryption Padding
        oaep = OAEP(len(bin(n)) - 2)
        padded_message = oaep.pad(message)
        print(f"Encrypted message with OAEP: {padded_message}")
        padded_int = int.from_bytes(padded_message, byteorder='big')
        encrypted_int = self.mod_pow(padded_int, e, n)
        # Debug: print the encrypted message with OAEP
        return encrypted_int
    
    def decrypt(self, ciphertext, key):
        d, n = key
        decrypted_int = self.mod_pow(ciphertext, d, n)
        decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
        # Add debug for see the decrypted message
        print(f"Decrypted message (before OAEP unpad): {decrypted_message}")
        
        oaep = OAEP(len(bin(n)) - 2)
        original_message = oaep.unpad(decrypted_message)
        return original_message
    
    def mod_pow(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if (exp & 1) == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result


class OAEP:
    def __init__(self, n_bits):
        self.k0 = 256  # SHA-256 output length
        self.k1 = 256  # Security parameter
        self.n_bits = n_bits
        self.n_bytes = (n_bits + 7) // 8

    def mgf1(self, seed, length):
        """Mask Generation Function based on SHA3-256"""
        if length > (2**32) *32:
            raise ValueError("Mask too long")
        
        result = b''
        counter = 0

        while len(result) < length:
            C = counter.to_bytes(4, byteorder='big')
            result += sha3_256(seed + C).digest()
            counter += 1

        return result[:length]

    def pad(self, message):
        """Apply OAEP padding to a message"""

        m_len = len(message)
        emlen = self.n_bytes - 1 # Reserve one byte for leading zero

        if m_len > emlen - 2 * (self.k0 // 8) -2:
            raise ValueError("Message too long")

        # Generate random seed
        seed = os.urandom(self.k0 // 8)

        # Create data block
        db = b'\x00' * (emlen - m_len - (self.k0 // 8) - 1) + b'\x01' + message

        # Generate masks
        db_mask = self.mgf1(seed, len(db))
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        seed_mask = self.mgf1(masked_db, self.k0 // 8)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        
        # Concatenate everything
        em = b'\x00' + masked_seed + masked_db
        return em

    def unpad(self, padded_msg):
        """Remove OAEP padding from a message"""
        if len(padded_msg) != self.n_bytes:
            raise ValueError(f"Decryption error: wrong message length")
            
        # Split the message
        if padded_msg[0] != 0:
            raise ValueError("Decryption error: wrong padding")
            
        masked_seed = padded_msg[1:1 + self.k0 // 8]
        masked_db = padded_msg[1 + self.k0 // 8:]
        
        # Recover seed
        seed_mask = self.mgf1(masked_db, self.k0 // 8)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        # Recover data block
        db_mask = self.mgf1(seed, len(masked_db))
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        
        # Find message boundary
        i = 0
        while i < len(db):
            if db[i] == 1:
                return db[i + 1:]
            elif db[i] != 0:
                raise ValueError("Decryption error: wrong padding")
            i += 1
            
        raise ValueError("Decryption error: no message found")

def sign(message, private_key):
    """Sign a message using RSA-SHA3"""
    hashed = sha3_256(message).digest()
    signature = int.from_bytes(hashed, byteorder='big')
    d, n = private_key
    signed = pow(signature, d, n)
    return base64.b64encode(signed.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))


def verify(message, signature, public_key):
    """Verify an RSA-SHA3 signature"""
    e, n = public_key
    signature = int.from_bytes(base64.b64decode(signature), byteorder='big')
    verified = pow(signature, e, n)
    hashed = int.from_bytes(sha3_256(message).digest(), byteorder='big')
    return verified == hashed

def verify_rsa_parameters(p, q, e, n):
    print("\nVerifying RSA parameters:")
    if not is_prime(p):
        print(f"Error: p = {p} is not prime!")
        return False
    print(f"✓ p = {p} is prime")

    if not is_prime(q):
        print(f"Error: q = {q} is not prime!")
        return False
    print(f"✓ q = {q} is prime")

    if p * q != n:
        print(f"Error: p * q = {p * q} does not equal n = {n}!")
        return False
    print(f"✓ p * q = {n}")

    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        print(f"Error: e = {e} is not coprime with φ(n) = {phi}!")
        return False
    print(f"✓ e = {e} is coprime with φ(n) = {phi}")

    return True

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True



# Example usage
if __name__ == "__main__":
    try:
        rsa_core = RSACore()
        print("Generating RSA keys...")
        pub_key, priv_key = rsa_core.generate_keypair()
        print(f"Public Key (e,n): {pub_key}")
        print(f"Private Key (d,n): {priv_key}")

        # Original Message
        message = b"Hello, RSA with OAEP and SHA3!"
        print(f"\nOriginal message: {message}")

        # Encrypt the message using the public key with OAEP
        encrypted_message = rsa_core.encrypt(message, pub_key)
        print(f"Encrypted Message: {encrypted_message}")

        # Decrypt the message using the private key with OAEP
        decrypted_message = rsa_core.decrypt(encrypted_message, priv_key)
        print(f"Decrypted Message: {decrypted_message}")

        # Signing the message
        print("\nSigning the message...")
        signature = sign(message, priv_key)
        print(f"Signature (Base64): {signature}")

        # Verifying the signature
        print("\nVerifying the signature...")
        is_valid = verify(message, signature, pub_key)
        print(f"Signature valid: {is_valid}")

        # Verify the whole process
        if message == decrypted_message and is_valid:
            print("\nSuccess! The message was correctly encrypted, decrypted, signed, and verified.")
        else:
            print("\nError: The process failed somewhere.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")