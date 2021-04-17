from typing import Any, Dict

from .const import COSE_KEY_TYPES


class COSEKey:
    """
    The interface class for a COSE Key used for mac, signing/verifying and encryption/decryption.
    """

    def __init__(self, cose_key: Dict[int, Any]):
        # Validate COSE Key common parameters.
        if 1 not in cose_key:
            raise ValueError("kty(1) not found.")
        if not isinstance(cose_key[1], int) and not isinstance(cose_key[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        try:
            self._kty: int = (
                cose_key[1]
                if isinstance(cose_key[1], int)
                else COSE_KEY_TYPES[cose_key[1]]
            )
        except ValueError:
            raise ValueError(f"Unknown kty: {cose_key[1]}")
        if 2 in cose_key and not isinstance(cose_key[2], bytes):
            raise ValueError("kid(2) should be bytes(bstr).")
        if 3 in cose_key and (
            not isinstance(cose_key[3], int) and not isinstance(cose_key[3], str)
        ):
            raise ValueError("alg(3) should be int str(tstr).")
        if 4 in cose_key and not isinstance(cose_key[4], list):
            raise ValueError("key_ops(4) should be list.")
        if 5 in cose_key and not isinstance(cose_key[5], bytes):
            raise ValueError("Base IV(5) should be bytes(bstr).")
        self._object = cose_key
        return

    @property
    def kty(self) -> int:
        return self._kty

    @property
    def kid(self) -> bytes:
        return self._object.get(2, None)

    @property
    def alg(self) -> int:
        return self._object.get(3, None)

    @property
    def key_ops(self) -> list:
        return self._object.get(4, None)

    @property
    def base_iv(self) -> bytes:
        return self._object.get(5, None)

    def sign(self, msg: bytes) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        raise NotImplementedError

    def verify(self, msg: bytes, sig: bytes):
        """
        Verifies that the specified digital signature is valid
        for the specified message.
        """
        raise NotImplementedError

    def encrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Encrypts the specified message.
        """
        raise NotImplementedError

    def decrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Decrypts the specified message.
        """
        raise NotImplementedError
