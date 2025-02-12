from rsa_core import RSACore
from rsaes_oaep import OAEP
from RSASP_RSAVP import RSASignature
import base64


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
        label = b"Certificado"

        # Assinatura da mensagem
        signature = RSASignature.sign(message, signing_priv_key)

        # Concatenar mensagem e assinatura
        combined_message = message + base64.b64decode(signature)

        # Calculate n_len from the public key
        n_len = (pub_key[1].bit_length() + 7) // 8  # pub_key[1] is the modulus n

        # Encryption with RSAES-OAEP using SHA-256
        oaep = OAEP(n_len, rsa_core=rsa,hash_algorithm='sha256')
        encrypted = oaep.rsaes_oaep_encrypt(pub_key, combined_message, label)

        print("Ciphertext:", encrypted.hex())

        # Decryption with RSAES-OAEP using SHA-256
        decrypted_combined = oaep.rsaes_oaep_decrypt(priv_key, encrypted, label)

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