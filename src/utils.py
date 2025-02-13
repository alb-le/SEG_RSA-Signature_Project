def bit_len(n: int):
    return len(bin(n - 1)) - 2


def octet_len(n: int):
    return (bit_len(n) + 7) // 8
