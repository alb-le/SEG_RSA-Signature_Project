from rsa_core import RSACore
from rsaes_oaep import OAEP
from rsa_signature import RSASignature
import base64

from src.utils import octet_len


def main():
    """Demonstration of RSA encryption, decryption, signing, and verification"""
    # Key generation
    rsa = RSACore(bits=2048)

    print("Generating RSA keys...")
    pub_key, priv_key = rsa.generate_keypair()
    print("keys:")
    print(f"public: {pub_key}")
    print(f"private: {priv_key}")

    print("Generating second keys...")
    signing_pub_key, signing_priv_key = rsa.generate_keypair()
    print("keys:")
    print(f"public: {signing_pub_key}")
    print(f"private: {signing_priv_key}")

    # Original message
    M = b"552"
    label = b""

    rsa_signature = RSASignature()
    # Assinatura da mensagem
    signature = rsa_signature.sign(M, signing_priv_key)
    print(f"Signature: {signature}")
    # Concatenar mensagem e assinatura

    # combined_message = M + base64Signature
    combined_message = M
    print(f"Combined message: {combined_message}")

    # Calculate n_len from the public key, the n_len is the length in octets of the RSA modulus n
    n = pub_key[1]
    n_len = octet_len(n)  # pub_key[1] is the modulus n
    print(f"n_len: {n_len}")
    # Encryption with RSAES-OAEP using the chosen hash algorithm
    oaep = OAEP(n_len, rsa_core=rsa)
    encrypted = oaep.rsaes_oaep_encrypt(pub_key, combined_message, label)

    print("Ciphertext:", encrypted.hex())

    # Decryption with RSAES-OAEP using the chosen hash algorithm
    decrypted_combined = oaep.rsaes_oaep_decrypt(priv_key, encrypted, label)

    # Separar mensagem e assinatura
    decrypted_message = decrypted_combined[:len(M)]
    decrypted_signature = base64.b64encode(decrypted_combined[len(M):])

    # Verificação da assinatura
    is_valid = rsa_signature.verify(decrypted_message, decrypted_signature, signing_pub_key)

    # Output results
    print(f"Original message: {M}")
    print(f"Decrypted message: {decrypted_message}")
    print(f"Signature valid: {is_valid}")

    assert M == decrypted_message, "Decryption failed"
    assert is_valid, "Signature verification failed"
    print("Success! RSA operations completed correctly.")


if __name__ == "__main__":
    rsa = RSACore(bits=2048)

    print("Generating RSA keys...")
    pub_key, priv_key = rsa.generate_keypair()
    print("keys:")
    print(f"public: {pub_key}")
    print(f"private: {priv_key}")
