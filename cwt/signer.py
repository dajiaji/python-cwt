from typing import Any, Dict, Union

from .cbor_processor import CBORProcessor
from .const import COSE_ALGORITHMS_SIGNATURE
from .cose_key import COSEKey
from .cose_key_interface import COSEKeyInterface
from .utils import to_cose_header


class Signer(CBORProcessor):
    """
    A Signer information.
    """

    def __init__(
        self,
        cose_key: COSEKeyInterface,
        protected: Union[Dict[int, Any], bytes],
        unprotected: Dict[int, Any],
        signature: bytes = b"",
    ):
        self._cose_key = cose_key
        if isinstance(protected, bytes):
            self._protected = protected
        else:
            self._protected = b"" if not protected else self._dumps(protected)
        self._unprotected = unprotected
        self._signature = signature
        return

    @property
    def cose_key(self) -> COSEKeyInterface:
        """
        The COSE key for the signer.
        """
        return self._cose_key

    @property
    def protected(self) -> bytes:
        """
        The parameters that are to be cryptographically protected.
        """
        return self._protected

    @property
    def unprotected(self) -> Dict[int, Any]:
        """
        The parameters that are not cryptographically protected.
        """
        return self._unprotected

    @property
    def signature(self) -> bytes:
        """
        The signature that the signer signed.
        """
        return self._signature

    @classmethod
    def new(
        cls,
        cose_key: COSEKeyInterface,
        protected: Union[dict, bytes] = {},
        unprotected: dict = {},
        signature: bytes = b"",
    ):
        """
        Create a signer information object (COSE_Signature).

        Args:
            key (COSEKey): A signature key for the signer.
            protected (Union[dict, bytes]): Parameters that are to be cryptographically
                protected.
            unprotected (dict): Parameters that are not cryptographically protected.
            signature (bytes): A signature as bytes.
        Returns:
            Signer: A signer information object.
        Raises:
            ValueError: Invalid arguments.
        """
        p: Union[Dict[int, Any], bytes] = (
            to_cose_header(protected, algs=COSE_ALGORITHMS_SIGNATURE)
            if isinstance(protected, dict)
            else protected
        )
        u = to_cose_header(unprotected, algs=COSE_ALGORITHMS_SIGNATURE)
        return cls(cose_key, p, u, signature)

    @classmethod
    def from_jwk(cls, data: Union[str, bytes, Dict[str, Any]]):
        """
        Create a signer information object (COSE_Signature) from JWK.
        The ``alg`` in the JWK will be included in the protected header,
        and the ``kid`` in the JWT will be include in the unprotected header.
        If you want to include any other parameters in the protected/unprotected
        header, you have to use :func:`Signer.new <cwt.Signer.new>`.

        Args:
            data (Union[str, bytes, Dict[str, Any]]): A JWK.
        Returns:
            Signer: A signer information object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        protected: Dict[int, Any] = {}
        unprotected: Dict[int, Any] = {}

        cose_key = COSEKey.from_jwk(data)

        # alg
        if cose_key.alg not in COSE_ALGORITHMS_SIGNATURE.values():
            raise ValueError(
                f"Unsupported or unknown alg for signature: {cose_key.alg}."
            )
        protected[1] = cose_key.alg

        # kid
        if cose_key.kid:
            unprotected[4] = cose_key.kid
        return cls(cose_key, protected, unprotected)

    @classmethod
    def from_pem(
        cls,
        data: Union[str, bytes],
        alg: Union[int, str] = "",
        kid: Union[bytes, str] = b"",
    ):
        """
        Create a signer information object (COSE_Signature) from PEM-formatted key.
        The ``alg`` in the JWK will be included in the protected header,
        and the ``kid`` in the JWT will be include in the unprotected header.
        If you want to include any other parameters in the protected/unprotected
        header, you have to use :func:`Signer.new <cwt.Signer.new>`.

        Args:
            data (Union[str, bytes]): A PEM-formatted key.
            alg (Union[int, str]): An algorithm label(int) or name(str). It is only
                used when an algorithm cannot be specified by the PEM data, such as
                RSA family algorithms.
            kid (Union[bytes, str]): A key identifier.
        Returns:
            Signer: A signer information object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        protected: Dict[int, Any] = {}
        unprotected: Dict[int, Any] = {}

        cose_key = COSEKey.from_pem(data, alg=alg, kid=kid)

        # alg
        protected[1] = cose_key.alg

        # kid
        if cose_key.kid:
            unprotected[4] = cose_key.kid
        return cls(cose_key, protected, unprotected)

    def sign(self, msg: bytes):
        """
        Returns a digital signature for the specified message
        using the specified key value.

        Args:
            msg (bytes): A message to be signed.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to sign the message.
        """
        self._signature = self._cose_key.sign(msg)
        return

    def verify(self, msg: bytes):
        """
        Verifies that the specified digital signature is valid
        for the specified message.

        Args:
            msg (bytes): A message to be verified.
        Raises:
            ValueError: Invalid arguments.
            VerifyError: Failed to verify.
        """
        self._cose_key.verify(msg, self._signature)
        return
