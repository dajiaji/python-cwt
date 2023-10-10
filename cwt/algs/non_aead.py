import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCTR:
    _MAX_SIZE = 2**31 - 1

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AESCTR key must be 128, 192, or 256 bits.")

        self._key = key

    @classmethod
    def generate_key(cls, bit_length: int) -> bytes:
        if not isinstance(bit_length, int):
            raise TypeError("bit_length must be an integer")

        if bit_length not in (128, 192, 256):
            raise ValueError("bit_length must be 128, 192, or 256")

        return os.urandom(bit_length // 8)

    def encrypt(
        self,
        nonce: bytes,
        data: bytes,
    ) -> bytes:
        encryptor = Cipher(
            algorithms.AES(self._key),
            modes.CTR(nonce),
        ).encryptor()

        return encryptor.update(data) + encryptor.finalize()

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
    ) -> bytes:
        decryptor = Cipher(
            algorithms.AES(self._key),
            modes.CTR(nonce),
        ).decryptor()

        return decryptor.update(data) + decryptor.finalize()


class AESCBC:
    _MAX_SIZE = 2**31 - 1

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AESCBC key must be 128, 192, or 256 bits.")

        self._key = key

    @classmethod
    def generate_key(cls, bit_length: int) -> bytes:
        if not isinstance(bit_length, int):
            raise TypeError("bit_length must be an integer")

        if bit_length not in (128, 192, 256):
            raise ValueError("bit_length must be 128, 192, or 256")

        return os.urandom(bit_length // 8)

    def encrypt(
        self,
        nonce: bytes,
        data: bytes,
    ) -> bytes:
        encryptor = Cipher(
            algorithms.AES(self._key),
            modes.CBC(nonce),
        ).encryptor()

        return encryptor.update(data) + encryptor.finalize()

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
    ) -> bytes:
        decryptor = Cipher(
            algorithms.AES(self._key),
            modes.CBC(nonce),
        ).decryptor()

        return decryptor.update(data) + decryptor.finalize()
