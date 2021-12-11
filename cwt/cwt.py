from calendar import timegm
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .claims import Claims
from .const import COSE_KEY_OPERATION_VALUES
from .cose import COSE
from .cose_key_interface import COSEKeyInterface
from .exceptions import DecodeError, VerifyError
from .recipient_interface import RecipientInterface
from .signer import Signer

CWT_DEFAULT_EXPIRES_IN = 3600  # 1 hour
CWT_DEFAULT_LEEWAY = 60  # 1 min


class CWT(CBORProcessor):
    """
    A CWT (CBOR Web Token) Implementaion, which is built on top of
    :class:`COSE <cwt.COSE>`

    ``cwt.cwt`` is a global object of this class initialized with default settings.
    """

    CBOR_TAG = 61

    def __init__(
        self,
        expires_in: int = CWT_DEFAULT_EXPIRES_IN,
        leeway: int = CWT_DEFAULT_LEEWAY,
        ca_certs: str = "",
    ):
        if not isinstance(expires_in, int):
            raise ValueError("expires_in should be int.")
        if expires_in <= 0:
            raise ValueError("expires_in should be positive number.")
        self._expires_in = expires_in

        if not isinstance(leeway, int):
            raise ValueError("leeway should be int.")
        if leeway <= 0:
            raise ValueError("leeway should be positive number.")
        self._leeway = leeway

        self._cose = COSE(
            kid_auto_inclusion=True,
            alg_auto_inclusion=True,
            verify_kid=True,
            ca_certs=ca_certs,
        )
        self._claim_names: Dict[str, int] = {}

    @classmethod
    def new(
        cls,
        expires_in: int = CWT_DEFAULT_EXPIRES_IN,
        leeway: int = CWT_DEFAULT_LEEWAY,
        ca_certs: str = "",
    ):
        """
        Constructor.

        Args:
            expires_in(int): The default lifetime in seconds of CWT
                (default value: ``3600``).
            leeway(int): The default leeway in seconds for validating
                ``exp`` and ``nbf`` (default value: ``60``).
            ca_certs(str): The path to a file which contains a concatenated list
                of trusted root certificates. You should specify private CA
                certificates in your target system. There should be no need to
                use the public CA certificates for the Web PKI.

        Examples:

            >>> from cwt import CWT, COSEKey
            >>> ctx = CWT.new(expires_in=3600*24, leeway=10)
            >>> key = COSEKey.from_symmetric_key(alg="HS256")
            >>> token = ctx.encode(
            ...     {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
            ...     key,
            ... )


            >>> from cwt import CWT, COSEKey
            >>> ctx = CWT.new(expires_in=3600*24, leeway=10, ca_certs="/path/to/ca_certs")
            >>> key = COSEKey.from_pem(alg="ES256")
            >>> token = ctx.encode(
            ...     {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
            ...     key,
            ... )
        """
        return cls(expires_in, leeway, ca_certs)

    @property
    def expires_in(self) -> int:
        """
        The default lifetime in seconds of CWT.
        If `exp` is not found in claims, this value will be used with current time.
        """
        return self._expires_in

    @expires_in.setter
    def expires_in(self, expires_in: int):
        if expires_in <= 0:
            raise ValueError("expires_in should be positive number.")
        self._expires_in = expires_in
        return

    @property
    def leeway(self) -> int:
        """
        The default leeway in seconds for validating ``exp`` and ``nbf``.
        """
        return self._leeway

    @leeway.setter
    def leeway(self, leeway: int):
        if leeway <= 0:
            raise ValueError("leeway should be positive number.")
        self._leeway = leeway
        return

    @property
    def cose(self) -> COSE:
        """
        The underlying COSE object.
        """
        return self._cose

    def encode(
        self,
        claims: Union[Claims, Dict[str, Any], Dict[int, Any], bytes],
        key: COSEKeyInterface,
        nonce: bytes = b"",
        recipients: Optional[List[RecipientInterface]] = None,
        signers: List[Signer] = [],
        tagged: bool = False,
    ) -> bytes:
        """
        Encodes CWT with MAC, signing or encryption.
        This is a wrapper function of the following functions for easy use:

        * :func:`encode_and_mac <cwt.CWT.encode_and_mac>`
        * :func:`encode_and_sign <cwt.CWT.encode_and_sign>`
        * :func:`encode_and_encrypt <cwt.CWT.encode_and_encrypt>`

        Therefore, it must be clear whether the use of the specified key is for MAC,
        signing, or encryption. For this purpose, the key must have the ``key_ops``
        parameter set to identify the usage.

        Args:
            claims (Union[Claims, Dict[str, Any], Dict[int, Any], bytes]): A CWT
                claims object, or a JWT claims object, text string or byte string.
            key (COSEKeyInterface): A COSE key used to generate a MAC for the claims.
            nonce (bytes): A nonce for encryption.
            recipients (Optional[List[RecipientInterface]]): A list of recipient
                information structures.
            signers (List[Signer]): A list of signer information structures for
                multiple signer cases.
            tagged (bool): An indicator whether the response is wrapped by CWT
                tag(61) or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        if isinstance(claims, Claims):
            return self._encode(claims, key, nonce, recipients, signers, tagged)
        if isinstance(claims, str):
            claims = claims.encode("utf-8")
        if isinstance(claims, bytes):
            try:
                claims = Claims.from_json(claims, self._claim_names)
            except ValueError:
                return self._encode(claims, key, nonce, recipients, signers, tagged)
        else:
            # Following code causes mypy error:
            # for k, v in claims.items():
            #     if isinstance(k, str):
            #         claims = Claims.from_json(claims)
            #     break
            # To avoid the error:
            json_claims: Dict[str, Any] = {}
            for k, v in claims.items():
                if isinstance(k, str):
                    json_claims[k] = v
            if json_claims:
                claims = Claims.from_json(json_claims, self._claim_names)
        return self._encode(claims, key, nonce, recipients, signers, tagged)

    def encode_and_mac(
        self,
        claims: Union[Claims, Dict[int, Any], bytes],
        key: COSEKeyInterface,
        recipients: Optional[List[RecipientInterface]] = None,
        tagged: bool = False,
    ) -> bytes:
        """
        Encodes with MAC.

        Args:
            claims (Union[Claims, Dict[int, Any], bytes]): A CWT claims object or byte
                string.
            key (COSEKeyInterface): A COSE key used to generate a MAC for the claims.
            recipients (Optional[List[RecipientInterface]]): A list of recipient
                information structures.
            tagged (bool): An indicator whether the response is wrapped by CWT
                tag(61) or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        if not isinstance(claims, Claims):
            self._validate(claims)
        else:
            claims = claims.to_dict()
        self._set_default_value(claims)
        b_claims = self._dumps(claims)
        res = self._cose.encode_and_mac(b_claims, key, {}, {}, recipients, out="cbor2/CBORTag")
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def encode_and_sign(
        self,
        claims: Union[Claims, Dict[int, Any], bytes],
        key: Optional[COSEKeyInterface] = None,
        signers: List[Signer] = [],
        tagged: bool = False,
    ) -> bytes:
        """
        Encodes CWT with signing.

        Args:
            claims (Claims, Union[Dict[int, Any], bytes]): A CWT claims object or
                byte string.
            key (Optional[COSEKeyInterface]): A COSE key or a list of the keys
               used to sign claims. When the ``signers`` parameter is set, this
               ``key`` parameter will be ignored and should not be set.
            signers (List[Signer]): A list of signer information structures for
                multiple signer cases.
            tagged (bool): An indicator whether the response is wrapped by CWT
                tag(61) or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        if not isinstance(claims, Claims):
            self._validate(claims)
        else:
            claims = claims.to_dict()
        self._set_default_value(claims)
        b_claims = self._dumps(claims)
        res = self._cose.encode_and_sign(b_claims, key, {}, {}, signers=signers, out="cbor2/CBORTag")
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def encode_and_encrypt(
        self,
        claims: Union[Claims, Dict[int, Any], bytes],
        key: COSEKeyInterface,
        nonce: bytes = b"",
        recipients: Optional[List[RecipientInterface]] = None,
        tagged: bool = False,
    ) -> bytes:
        """
        Encodes CWT with encryption.

        Args:
            claims (Claims, Union[Dict[int, Any], bytes]): A CWT claims object or
                byte string.
            key (COSEKeyInterface): A COSE key used to encrypt the claims.
            nonce (bytes): A nonce for encryption.
            recipients (List[RecipientInterface]): A list of recipient information
                structures.
            tagged (bool): An indicator whether the response is wrapped by CWT
                tag(61) or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        if not isinstance(claims, Claims):
            self._validate(claims)
        else:
            claims = claims.to_dict()
        self._set_default_value(claims)
        b_claims = b""
        if isinstance(claims, dict):
            b_claims = self._dumps(claims)
        else:
            b_claims = claims
        res = self._cose.encode_and_encrypt(
            b_claims,
            key,
            {},
            {},
            nonce,
            recipients,
            out="cbor2/CBORTag",
        )
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def decode(
        self,
        data: bytes,
        keys: Union[COSEKeyInterface, List[COSEKeyInterface]],
        no_verify: bool = False,
    ) -> Union[Dict[int, Any], bytes]:
        """
        Verifies and decodes CWT.

        Args:
            data (bytes): A byte string of an encoded CWT.
            keys (Union[COSEKeyInterface, List[COSEKeyInterface]]): A COSE key
                or a list of the keys used to verify and decrypt the encoded CWT.
            no_verify (bool): An indicator whether token verification is skiped
                or not.
        Returns:
            Union[Dict[int, Any], bytes]: A byte string of the decoded CWT.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the CWT.
            VerifyError: Failed to verify the CWT.
        """
        cwt: Union[bytes, CBORTag, Dict[int, Any]] = self._loads(data)
        if isinstance(cwt, CBORTag) and cwt.tag == CWT.CBOR_TAG:
            cwt = cwt.value
        keys = [keys] if isinstance(keys, COSEKeyInterface) else keys
        while isinstance(cwt, CBORTag):
            cwt = self._cose.decode(cwt, keys)
            cwt = self._loads(cwt)
        if not no_verify:
            self._verify(cwt)
        return cwt

    def set_private_claim_names(self, claim_names: Dict[str, int]):
        """
        Sets private claim definitions. The definitions will be used in
        :func:`encode <cwt.CWT.encode>` when it is called with JSON-based claims.

        Args:
            claim_names (Dict[str, int]): A set of private claim definitions which
                consist of a readable claim name(str) and a claim key(int).
                The claim key should be less than -65536 but you  can use the
                numbers other than pre-registered numbers listed in
                `IANA Registry <https://www.iana.org/assignments/cose/cose.xhtml>`_.
        Raises:
            ValueError: Invalid arguments.
        """
        self._claim_names = claim_names
        return

    def _encode(
        self,
        claims: Union[Claims, Dict[Any, Any], bytes],
        key: COSEKeyInterface,
        nonce: bytes = b"",
        recipients: Optional[List[RecipientInterface]] = None,
        signers: List[Signer] = [],
        tagged: bool = False,
    ) -> bytes:
        if COSE_KEY_OPERATION_VALUES["sign"] in key.key_ops:
            if [ops for ops in key.key_ops if ops in [3, 4, 9, 10]]:
                raise ValueError("The key operation could not be specified.")
            return self.encode_and_sign(claims, key, signers, tagged)
        if COSE_KEY_OPERATION_VALUES["encrypt"] in key.key_ops:
            if [ops for ops in key.key_ops if ops in [1, 2, 9, 10]]:
                raise ValueError("The key operation could not be specified.")
            return self.encode_and_encrypt(claims, key, nonce, recipients, tagged)
        if COSE_KEY_OPERATION_VALUES["MAC create"] in key.key_ops:
            if [ops for ops in key.key_ops if ops in [1, 2, 3, 4]]:
                raise ValueError("The key operation could not be specified.")
            return self.encode_and_mac(claims, key, recipients, tagged)
        raise ValueError("The key operation could not be specified.")

    def _validate(self, claims: Union[Dict[int, Any], bytes]):
        if isinstance(claims, bytes):
            try:
                nested = self._loads(claims)
            except Exception:
                raise ValueError("Invalid claim format.")
            if not isinstance(nested, CBORTag):
                raise ValueError("A bytes-formatted claims needs CBOR(COSE) Tag.")
            if nested.tag not in [16, 96, 17, 97, 18, 98]:
                raise ValueError(f"Unsupported or unknown CBOR tag({nested.tag}).")
            return
        Claims.validate(claims)
        return

    def _verify(self, claims: Union[Dict[int, Any], bytes]):
        if not isinstance(claims, dict):
            raise DecodeError("Failed to decode.")

        now = timegm(datetime.now(tz=timezone.utc).utctimetuple())
        if 4 in claims:  # exp
            if isinstance(claims[4], int) or isinstance(claims[4], float):
                if claims[4] < (now - self._leeway):
                    raise VerifyError("The token has expired.")
            else:
                raise ValueError("exp should be int or float.")

        if 5 in claims:  # nbf
            if isinstance(claims[5], int) or isinstance(claims[5], float):
                if claims[5] > (now + self._leeway):
                    raise VerifyError("The token is not yet valid.")
            else:
                raise ValueError("nbf should be int or float.")
        return

    def _set_default_value(self, claims: Union[Dict[int, Any], bytes]):
        if isinstance(claims, bytes):
            return
        now = timegm(datetime.now(tz=timezone.utc).utctimetuple())
        if 4 not in claims:
            claims[4] = now + self._expires_in
        if 5 not in claims:
            claims[5] = now
        if 6 not in claims:
            claims[6] = now
        return


# export
_cwt = CWT()


def encode(
    claims: Union[Claims, Dict[str, Any], Dict[int, Any], bytes],
    key: COSEKeyInterface,
    nonce: bytes = b"",
    recipients: Optional[List[RecipientInterface]] = None,
    signers: List[Signer] = [],
    tagged: bool = False,
) -> bytes:

    return _cwt.encode(claims, key, nonce, recipients, signers, tagged)


def encode_and_mac(
    claims: Union[Claims, Dict[int, Any], bytes],
    key: COSEKeyInterface,
    recipients: Optional[List[RecipientInterface]] = None,
    tagged: bool = False,
) -> bytes:

    return _cwt.encode_and_mac(claims, key, recipients, tagged)


def encode_and_sign(
    claims: Union[Claims, Dict[int, Any], bytes],
    key: Optional[COSEKeyInterface] = None,
    signers: List[Signer] = [],
    tagged: bool = False,
) -> bytes:

    return _cwt.encode_and_sign(claims, key, signers, tagged)


def encode_and_encrypt(
    claims: Union[Claims, Dict[int, Any], bytes],
    key: COSEKeyInterface,
    nonce: bytes = b"",
    recipients: Optional[List[RecipientInterface]] = None,
    tagged: bool = False,
) -> bytes:

    return _cwt.encode_and_encrypt(claims, key, nonce, recipients, tagged)


def decode(
    data: bytes,
    keys: Union[COSEKeyInterface, List[COSEKeyInterface]],
    no_verify: bool = False,
) -> Union[Dict[int, Any], bytes]:

    return _cwt.decode(data, keys, no_verify)


def set_private_claim_names(claim_names: Dict[str, int]):

    return _cwt.set_private_claim_names(claim_names)
