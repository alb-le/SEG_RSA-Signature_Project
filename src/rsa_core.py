import random
import os
import base64
from hashlib import sha256

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

    def encrypt(self, message, key):
        e, n = key
        return self.mod_pow(message, e, n)
    
    def decrypt(self, ciphertext, key):
        d, n = key
        return self.mod_pow(ciphertext, d, n)
    
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
    def __init__(self, n_len):
        self.k0 = 256  # SHA-256 output length
        self.k1 = 256  # Security parameter
        self.n_len = n_len

    def mgf1(self, seed, length):
        """Mask Generation Function"""
        result = b''
        counter = 0
        while len(result) < length:
            C = counter.to_bytes(4, 'big')
            result += sha256(seed + C).digest()
            counter += 1
        return result[:length]

    def pad(self, message):
        """OAEP Padding"""
        m_len = len(message)
        if m_len > self.n_len - self.k0 - self.k1 - 2:
            raise ValueError("Message too long")

        # Generate random padding
        r = os.urandom(self.k0)
        
        # Create padded message
        db = b'\x00' * self.k1 + message + b'\x01'
        db_mask = self.mgf1(r, len(db))
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        seed_mask = self.mgf1(masked_db, self.k0)
        masked_seed = bytes(a ^ b for a, b in zip(r, seed_mask))
        
        return masked_seed + masked_db

    def unpad(self, padded):
        """OAEP Unpadding"""

        print(f"Length of padded message: {len(padded)}")
        print(f"Value of self.k0: {self.k0}")
        masked_seed = padded[:self.k0]
        masked_db = padded[self.k0:]

        # Print the lengths of masked_seed and masked_db
        print(f"Length of masked_seed: {len(masked_seed)}")
        print(f"Length of masked_db: {len(masked_db)}")

         # Ensure masked_db is not empty
        if len(masked_db) == 0:
            raise ValueError("masked_db is empty, check the slicing operation")
    
        seed_mask = self.mgf1(masked_db, self.k0)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        db_mask = self.mgf1(seed, len(masked_db))
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        print(f"masked_seed: {masked_seed}")
        print(f"masked_db: {masked_db}")
        print(f"seed_mask: {seed_mask}")
        print(f"seed: {seed}")
        print(f"db_mask: {db_mask}")
        print(f"db: {db}")

        
        # Find message in unpadded data
        i = self.k1
        while i < len(db):
            if db[i] == 1:
                return db[i+1:]
            i += 1
        raise ValueError("Invalid padding")

def sign(message, private_key):
    hashed = int.from_bytes(sha3_256(message).digest(), byteorder='big')
    signature = rsa_core.encrypt(hashed, private_key)
    return base64.b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big'))

def verify(message, signature, public_key):
    hashed = int.from_bytes(sha3_256(message).digest(), byteorder='big')
    signature = int.from_bytes(base64.b64decode(signature), byteorder='big')
    decrypted_hash = rsa_core.decrypt(signature, public_key)
    return hashed == decrypted_hash

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
    rsa_core = RSACore()
    print("Generating RSA keys...")
    pub_key, priv_key = rsa_core.generate_keypair()
    print(f"Public Key (e,n): {pub_key}")
    print(f"Private Key (d,n): {priv_key}")

    message = b"Hello, RSA with OAEP and SHA3!"
    
    # Apply OAEP padding
    oaep = OAEP(1024)
    padded_message = oaep.pad(message)
    print(f"Padded Message: {padded_message}")

    # Encrypt the padded message using the public key
    encrypted_message = rsa_core.encrypt(int.from_bytes(padded_message, byteorder='big'), pub_key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message using the private key
    decrypted_message = rsa_core.decrypt(encrypted_message, priv_key)
    decrypted_message_bytes = decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, byteorder='big')
    print(f"Decrypted Message (padded): {decrypted_message_bytes}")

    # Remove OAEP padding
    original_message = oaep.unpad(decrypted_message_bytes)
    print(f"Original Message: {original_message}")

    # Signing the message
    print("\nSigning the message...")
    signature = sign(message, priv_key)
    print(f"Signature (Base64): {signature}")

    # Verifying the signature
    print("\nVerifying the signature...")
    is_valid = verify(message, signature, pub_key)
    print(f"Signature valid: {is_valid}")