from typing import Any, Dict

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
        return

    @property
    def key(self) -> bytes:
        """
        A body of the symmetric key.
        """
        raise NotImplementedError("Symmetric key only supports 'key' property.")

    @property
    def crv(self) -> int:
        """
        A curve of the key type.
        """
        raise NotImplementedError("OKP and EC2 key support 'crv' property.")

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
