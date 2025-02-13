from rsa_core import RSACore
from rsaes_oaep import OAEP
from rsa_signature import RSASignature

from src.message_delivery_service import MessageDeliveryService
from src.utils import octet_len

if __name__ == "__main__":
    rsa = RSACore(bits=2048)

    print("Gerando chaves...")
    pub_key, priv_key = rsa.generate_keypair()
    print("chaves 1:")
    print(f"public: {pub_key}")
    print(f"private: {priv_key}")

    print("Gerando chaves...")
    pub_key_reciver, priv_key_reciver = rsa.generate_keypair()
    print("chaves 2:")
    print(f"public: {pub_key_reciver}")
    print(f"private: {priv_key_reciver}")

    n = pub_key[1]
    n_len = octet_len(n)
    n2 = pub_key_reciver[1]
    n_len2 = octet_len(n2)

    msg_clara = b"msg"

    oaep = OAEP(n_len, rsa_core=rsa)
    encrypted = oaep.rsaes_oaep_encrypt(msg_clara, pub_key)
    decrypted = oaep.rsaes_oaep_decrypt(encrypted, priv_key)

    print(f"Mensagem clara: {msg_clara}")
    print(f"Mensagem encriptada: {encrypted}")
    print(f"Mensagem decriptada: {decrypted}")

    rsa_signature = RSASignature()

    delivery_service = MessageDeliveryService(oaep=oaep, rsa_signature=rsa_signature)

    C_msg, msg_len = delivery_service.send_signed(message=msg_clara,
                                                  private_key_sender=priv_key,
                                                  public_key_receiver=pub_key_reciver)
    print(f"\n\nMensagem enviada: {msg_clara}")

    decrypted_msg = delivery_service.recive_signed(data=C_msg,
                                                   private_key_receiver=priv_key_reciver,
                                                   public_key_sender=pub_key,
                                                   message_len=msg_len)
    print(f"Mensagem recebida: {decrypted_msg}")
    fim = "---------"
    print(fim * 10)
