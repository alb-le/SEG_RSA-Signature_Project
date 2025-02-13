from src.rsa_signature import RSASignature
from src.rsaes_oaep import OAEP
from src.utils import b64


class MessageDeliveryService:
    def __init__(self, oaep: OAEP, rsa_signature: RSASignature):
        self.rsa_core = oaep.rsa_core
        self.hash_func = oaep.hash_func
        self.n_len = oaep.n_len  # Size of RSA modulus in bytes
        self.hLen = oaep.hLen
        self.rsa_signature = rsa_signature
        self.oaep = oaep
        self.increment = self.n_len - 2 * self.hLen - 2

    @staticmethod
    def message_len(message: bytes) -> bytes:
        return (len(message) | 2 ** 15).to_bytes(2, "big")

    def send_signed(self, message: bytes, private_key_sender, public_key_receiver):
        signature = self.rsa_signature.sign(message, private_key_sender)
        print(f"\n\nSignature: {signature}")

        msg_signed = message + signature

        i = 0
        C = b''
        while i < len(msg_signed):
            ii = i + self.increment
            c = self.oaep.rsaes_oaep_encrypt(msg_signed[i:ii], public_key_receiver)
            i = ii
            C = C + c
        M = b64.encode(C)

        msg_len = len(message)
        return M, msg_len

    def recive_signed(self, data: bytes, private_key_receiver, public_key_sender, message_len):
        message = b64.decode(data)

        M = b""
        i = 0
        ii = 0
        while ii < len(message):
            ii += self.n_len
            M_ = self.oaep.rsaes_oaep_decrypt(message[i:ii], private_key_receiver)
            i = ii
            M = M + M_

        msg_signed = M
        recived_hash = msg_signed[message_len:]
        message = msg_signed[:message_len]
        is_valid = self.rsa_signature.verify(message, recived_hash, public_key_sender)

        if is_valid:
            return message
        else:
            return None
