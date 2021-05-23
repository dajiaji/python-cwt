from typing import Any, Dict, List

from .const import COSE_KEY_TYPES
from .cose_key_common import COSEKeyCommon


class COSEKey(COSEKeyCommon):
    """
    The interface class for a COSE Key used for MAC, signing/verifying and encryption/decryption.
    """

    def __init__(self, params: Dict[int, Any]):
        """
        Constructor.

        Args:
            params (Dict[int, Any]): A COSE key common parameters object formatted to a CBOR-like dictionary.
        """

        super().__init__(params)

        # kty
        if 1 not in params:
            raise ValueError("kty(1) not found.")
        if not isinstance(params[1], int) and not isinstance(params[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if isinstance(params[1], int) and params[1] not in [1, 2, 3, 4, 5, 6]:
            raise ValueError(f"Unknown kty: {params[1]}")
        if isinstance(params[1], str) and params[1] not in COSE_KEY_TYPES:
            raise ValueError(f"Unknown kty: {params[1]}")
        self._kty: int = (
            params[1] if isinstance(params[1], int) else COSE_KEY_TYPES[params[1]]
        )

        # key_ops
        if 4 in params and not isinstance(params[4], list):
            raise ValueError("key_ops(4) should be list.")
        self._key_ops: List[int] = params[4] if 4 in params else []
        return

    @property
    def kty(self) -> int:
        """
        Identification of the key type.
        """
        return self._kty

    @property
    def key_ops(self) -> List[int]:
        """
        Restrict set of permissible operations.
        """
        return self._key_ops

    def to_dict(self) -> Dict[int, Any]:
        """
        Returns a CBOR-like structure (Dict[int, Any]) of the COSE key.

        Returns:
            Dict[int, Any]: A CBOR-like structure of the COSE key.
        """
        res: Dict[int, Any] = {1: self._kty}
        if self._kid:
            res[2] = self._kid
        if self._alg:
            res[3] = self._alg
        if self._key_ops:
            res[4] = self._key_ops
        if self._base_iv:
            res[5] = self._base_iv
        return res

    def generate_nonce(self) -> bytes:
        """
        Returns a nonce with a size suitable for the algorithm.
        This function will be called internally in :class:`CWT <cwt.CWT>`
        when no nonce is specified by the application.
        This function adopts ``secrets.token_bytes()`` to generate a nonce.
        If you do not want to use it, you should explicitly set a nonce to
        :class:`CWT <cwt.CWT>` functions
        (e.g., :func:`encode_and_encrypt <cwt.CWT.encode_and_encrypt>`).

        Returns:
            bytes: A byte string of a generated nonce.
        Raises:
            NotImplementedError: Not implemented.
        """
        raise NotImplementedError

    def sign(self, msg: bytes) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.

        Args:
            msg (bytes): A message to be signed.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to sign the message.
        """
        raise NotImplementedError

    def verify(self, msg: bytes, sig: bytes):
        """
        Verifies that the specified digital signature is valid
        for the specified message.

        Args:
            msg (bytes): A message to be verified.
            sig (bytes): A digital signature of the message.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            VerifyError: Failed to verify.
        """
        raise NotImplementedError

    def encrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Encrypts the specified message.

        Args:
            msg (bytes): A message to be encrypted.
            nonce (bytes): A nonce for encryption.
            aad (bytes): Additional authenticated data.
        Returns:
            bytes: A byte string of encrypted data.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to encrypt the message.
        """
        raise NotImplementedError

    def decrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Decrypts the specified message.

        Args:
            msg (bytes): An encrypted message.
            nonce (bytes): A nonce for encryption.
            aad (bytes): Additional authenticated data.
        Returns:
            bytes: A byte string of the decrypted data.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            DecodeError: Failed to decrypt the message.
        """
        raise NotImplementedError
