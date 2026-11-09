from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .algs.ec2 import EC2Key
from .algs.okp import OKPKey
from .cbor_processor import CBORProcessor
from .cose_key_interface import COSEKeyInterface


class RecipientInterface(CBORProcessor):
    """
    The interface class for a COSE Recipient.
    """

    def __init__(
        self,
        protected: dict[str | int, Any] | None = None,
        unprotected: dict[str | int, Any] | None = None,
        ciphertext: bytes = b"",
        recipients: list[Any] = [],
        key_ops: list[int] = [],
        key: bytes = b"",
    ):
        """
        Constructor.

        Args:
            protected (dict[int, Any] | None): Parameters that are to be cryptographically
                protected.
            unprotected (dict[int, Any] | None): Parameters that are not cryptographically
                protected.
            ciphertext: A ciphertext encoded as bytes.
            recipients: A list of recipient information structures.
            key_ops: A list of operations that the key is to be used for.
            key: A body of the key as bytes.
        """
        protected = {} if protected is None else protected
        unprotected = {} if unprotected is None else unprotected
        self._alg = 0

        # kid
        self._kid = b""
        if 4 in protected:
            if not isinstance(protected[4], bytes):
                raise ValueError("protected[4](kid) should be bytes.")
            self._kid = protected[4]
        elif 4 in unprotected:
            if not isinstance(unprotected[4], bytes):
                raise ValueError("unprotected[4](kid) should be bytes.")
            self._kid = unprotected[4]

        # alg
        if 1 in protected:
            if not isinstance(protected[1], int):
                raise ValueError("protected[1](alg) should be int.")
            self._alg = protected[1]
        elif 1 in unprotected:
            if not isinstance(unprotected[1], int):
                raise ValueError("unprotected[1](alg) should be int.")
            self._alg = unprotected[1]
            if unprotected[1] == -6:  # direct
                if len(protected) != 0:
                    raise ValueError("protected header should be empty.")
                if len(ciphertext) != 0:
                    raise ValueError("ciphertext should be zero-length bytes.")
                if len(recipients) != 0:
                    raise ValueError("recipients should be absent.")

        # iv
        if 5 in unprotected:
            if not isinstance(unprotected[5], bytes):
                raise ValueError("unprotected[5](iv) should be bytes.")

        self._b_protected: bytes | None = None
        self._protected = protected
        self._unprotected = unprotected
        self._ciphertext = ciphertext
        self._key = key
        self._context: list[Any] = [0, [None, None, None], [None, None, None], [None, None]]

        # Validate recipients
        self._recipients: list[RecipientInterface] = []
        if not recipients:
            return
        for recipient in recipients:
            if not isinstance(recipient, RecipientInterface):
                raise ValueError("Invalid child recipient.")
            self._recipients.append(recipient)
        return

    @property
    def kid(self) -> bytes:
        """
        The key identifier.
        """
        return self._kid

    @property
    def alg(self) -> int:
        """
        The algorithm that is used with the key.
        """
        return self._alg

    @property
    def protected(self) -> dict[str | int, Any]:
        """
        The parameters that are to be cryptographically protected.
        """
        return self._protected

    @property
    def b_protected(self) -> bytes:
        """
        The binary encoded protected header.
        """
        if self._b_protected is None:
            return self._dumps(self._protected)
        return self._b_protected

    @property
    def unprotected(self) -> dict[str | int, Any]:
        """
        The parameters that are not cryptographically protected.
        """
        return self._unprotected

    @property
    def ciphertext(self) -> bytes:
        """
        The ciphertext encoded as bytes
        """
        return self._ciphertext

    @property
    def recipients(self) -> list[Any]:
        """
        The list of recipient information structures.
        """
        return self._recipients

    @property
    def context(self) -> list[Any]:
        """
        The recipient context information.
        """
        return self._context

    def to_list(self) -> list[Any]:
        """
        Returns the recipient information as a COSE recipient structure.

        Returns:
            list[Any]: The recipient structure.
        """
        b_protected = self._dumps(self._protected) if self._protected else b""
        b_ciphertext = self._ciphertext if self._ciphertext else b""
        res: list[Any] = [b_protected, self._unprotected, b_ciphertext]
        if not self._recipients:
            return res

        children = []
        for recipient in self._recipients:
            children.append(recipient.to_list())
        res.append(children)
        return res

    def encode(
        self,
        plaintext: bytes = b"",
        aad: bytes = b"",
    ) -> tuple[list[Any], COSEKeyInterface | None]:
        """
        Encrypts a specified plaintext to the ciphertext in the COSE_Recipient
        structure with the recipient-specific method (e.g., key wrapping, key
        agreement, or the combination of them) and sets up the related information
        (context information or ciphertext) in the recipient structure.

        This function will be called in COSE.encode_* functions so applications
        do not need to call it directly.

        Args:
            plaintext (bytes): A plaing text to be encrypted. In most of the cases,
                the plaintext is a byte string of a content encryption key.
            external_aad (bytes): External additional authenticated data for AEAD.
            aad_context (bytes): An additional authenticated data context to build
                an Enc_structure internally.
        Returns:
            tuple[list[Any], COSEKeyInterface | None]: The encoded COSE_Recipient structure
                and a derived key.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode(e.g., wrap, derive) the key.
        """
        raise NotImplementedError

    def decode(
        self,
        key: COSEKeyInterface,
        aad: bytes = b"",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> bytes | COSEKeyInterface:
        """
        Decrypts the ciphertext in the COSE_Recipient structure with the
        recipient-specific method (e.g., key wrapping, key agreement,
        or the combination of them).

        This function will be called in COSE.decode so applications do not need
        to call it directly.

        Args:
            key (COSEKeyInterface): The external key to be used for
                decrypting the ciphertext in the COSE_Recipient structure.
            external_aad (bytes): External additional authenticated data for AEAD.
            aad_context (bytes): An additional authenticated data context to build
                an Enc_structure internally.
            alg (int): The algorithm of the key derived.
            as_cose_key (bool): The indicator whether the output will be returned
                as a COSEKey or not.
        Returns:
            bytes | COSEKeyInterface: The decrypted ciphertext field or The COSEKey
                converted from the decrypted ciphertext.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode(e.g., unwrap, derive) the key.
        """
        raise NotImplementedError

    def _to_cose_key(self, k: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey) -> dict[int, Any]:
        if isinstance(k, EllipticCurvePublicKey):
            return EC2Key.to_cose_key(k)
        return OKPKey.to_cose_key(k)

    def _set_b_protected(self, b_protected: bytes):
        self._b_protected = b_protected
        return
