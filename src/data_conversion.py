def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive (I2OSP)
    Converts a nonnegative integer x to an octet string of a specified length x_len.
    
    :param x: Nonnegative integer to be converted
    :param x_len: Intended length of the resulting octet string
    :return: Corresponding octet string of length x_len
    :raises ValueError: If the integer is too large to fit in the specified length
    """
    if x >= 256 ** x_len:
        raise ValueError("integer too large")
    
    octet_string = x.to_bytes(x_len, byteorder='big')
    return octet_string

def os2ip(octet_string: bytes) -> int:
    """
    Octet-String-to-Integer primitive (OS2IP)
    Converts an octet string to a nonnegative integer.
    
    :param octet_string: Octet string to be converted
    :return: Corresponding nonnegative integer
    """
    integer = int.from_bytes(octet_string, byteorder='big')
    return integer