from typing import Any, Dict

from .const import COSE_KEY_TYPES


class COSEKey:
    """
    The interface class for a COSE Key used for MAC, signing/verifying and encryption/decryption.
    """

    def __init__(self, cose_key: Dict[int, Any]):
        """
        Constructor.

        Args:
            cose_key (Dict[int, Any]): A COSE key formatted to a CBOR-like dictionary.
        """
        # Validate COSE Key common parameters.
        if 1 not in cose_key:
            raise ValueError("kty(1) not found.")
        if not isinstance(cose_key[1], int) and not isinstance(cose_key[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if isinstance(cose_key[1], int) and cose_key[1] not in [1, 2, 3, 4, 5, 6]:
            raise ValueError(f"Unknown kty: {cose_key[1]}")
        if isinstance(cose_key[1], str) and cose_key[1] not in COSE_KEY_TYPES:
            raise ValueError(f"Unknown kty: {cose_key[1]}")
        self._kty: int = (
            cose_key[1] if isinstance(cose_key[1], int) else COSE_KEY_TYPES[cose_key[1]]
        )
        if 2 in cose_key and not isinstance(cose_key[2], bytes):
            raise ValueError("kid(2) should be bytes(bstr).")
        if 3 in cose_key and (
            not isinstance(cose_key[3], int) and not isinstance(cose_key[3], str)
        ):
            raise ValueError("alg(3) should be int or str(tstr).")
        if 4 in cose_key and not isinstance(cose_key[4], list):
            raise ValueError("key_ops(4) should be list.")
        if 5 in cose_key and not isinstance(cose_key[5], bytes):
            raise ValueError("Base IV(5) should be bytes(bstr).")
        self._object = cose_key
        return

    @property
    def key(self) -> bytes:
        """
        A body of the symmetric key.
        """
        raise NotImplementedError("Symmetric key only supports 'key' property.")

    @property
    def kty(self) -> int:
        """
        Identification of the key type.
        """
        return self._kty

    @property
    def kid(self) -> bytes:
        """
        A key identification value.
        """
        return self._object.get(2, None)

    @property
    def alg(self) -> int:
        """
        An algorithm that is used with the key.
        """
        return self._object.get(3, None)

    @property
    def crv(self) -> int:
        """
        A curve of the key type.
        """
        raise NotImplementedError("OKP and EC2 key support 'crv' property.")

    @property
    def key_ops(self) -> list:
        """
        Restrict set of permissible operations.
        """
        return self._object.get(4, None)

    @property
    def base_iv(self) -> bytes:
        """
        Base IV to be xor-ed with Partial IVs.
        """
        return self._object.get(5, None)

    def to_dict(self) -> Dict[int, Any]:
        """
        Returns a CBOR-like structure (Dict[int, Any]) of the COSE key.

        Returns:
            Dict[int, Any]: A CBOR-like structure of the COSE key.
        """
        return self._object

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
