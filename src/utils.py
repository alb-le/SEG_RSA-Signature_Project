import base64


def bit_len(n: int):
    return len(bin(n - 1)) - 2


def octet_len(n: int):
    return (bit_len(n) + 7) // 8

class b64:
    encode = lambda x: base64.b64encode(x)
    decode = lambda x: base64.b64decode(x)
