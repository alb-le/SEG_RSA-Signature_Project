import random
from hashlib import sha3_256
class RSACore:
    def __init__(self, bits=2048, public_exponent=65537):
        """
        Initialize RSA parameters with specified bit length and public exponent.
        bits: length in bits of the RSA modulus n
        public_exponent: RSA public exponent (e)
        """
        self.bits = bits
        self.e = public_exponent  # Commonly used public exponent

    #
    def generate_prime_candidate(self):  # Generate a random prime candidate with specified bit length
        # Generate random odd integer of specified bits
        #Return a candidate prime number (r_i)
        candidate = random.getrandbits(self.bits)
        candidate |= (1 << self.bits - 1) | 1  # Set MSB and LSB to 1
        return candidate

    def miller_rabin_test(self, n, k=128):
        """
        Perform Miller-Rabin primality test on the given number n with k iterations.
        n: number to be tested for primality
        k: number of iterations for accuracy
        Return True if n is probably prime, False otherwise
        """
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
        """
        Generate a prime number using the Miller-Rabin test.
        Return a prime number (r_i)
        """
        while True:
            prime_candidate = self.generate_prime_candidate()
            if self.miller_rabin_test(prime_candidate):
                return prime_candidate

    def generate_keypair(self):
        """
        Generate RSA public and private key pair.
        n = RSA modulus, n = p * q
        e = RSA public exponent
        d = RSA private exponent
        Return (public_key, private_key)
        """
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
        #RSAEP implementation (Section 5.1.1)
        """
        RSA encryption primitive (RSAEP).
        public_key: (n, e) tuple
        m: message representative, an integer between 0 and n-1
        Return ciphertext representative (c)
        """
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
        #RSADP implementation (Section 5.1.2)
        """
        RSA decryption primitive (RSADP).
        private_key: (n, d) tuple
        c: ciphertext representative, an integer between 0 and n-1
        Return message representative (m)
        """
        n, d = private_key

        if not (0 <= c < n):
            raise ValueError("ciphertext representative out of range")

        return pow(c, d, n)