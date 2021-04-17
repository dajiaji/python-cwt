from typing import List


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes(length=(8 + (n + (n < 0)).bit_length()) // 8, byteorder='big')

def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    """
    if x >= 256 ** x_len:
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(x_len - len(digits)):
        digits.append(0)
    return bytes.fromhex("".join("%.2x" % x for x in digits[::-1]))


def os2ip(octet_string: List[int]) -> int:
    """
    Octet-String-to-Integer primitive
    """
    x_len = len(octet_string)
    octet_string = octet_string[::-1]
    x = 0
    for i in range(x_len):
        x += octet_string[i] * 256 ** i
    return x
