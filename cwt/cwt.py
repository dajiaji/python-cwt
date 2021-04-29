from calendar import timegm
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .cose import COSE
from .cose_key import COSEKey
from .exceptions import VerifyError
from .recipient import Recipient

_CWT_DEFAULT_EXPIRES_IN = 3600  # 1 hour
_CWT_DEFAULT_LEEWAY = 60  # 1 min


class CWT(CBORProcessor):
    """
    A CWT (CBOR Web Token) Implementaion, which is built on top of
    :class:`COSE <cwt.COSE>`

    ``cwt.cwt`` is a global object of this class initialized with default settings.
    """

    CBOR_TAG = 61

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Constructor.

        Args:
            options (Optional[Dict[str, Any]]): Options for the initial
                configuration of CWT. At this time, ``expires_in`` (default
                value: ``3600`` ) and ``leaway`` (default value: ``60``) are
                only supported. See also :func:`expires_in <cwt.CWT.expires_in>`,
                :func:`leeway <cwt.CWT.leeway>`.

        Examples:

            >>> from cwt import CWT, claims, cose_key
            >>> ctx = CWT({"expires_in": 3600*24, "leeway": 10})
            >>> key = cose_key.from_symmetric_key("mysecret")
            >>> token = ctx.encode_and_mac(
            ...     claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            ...     key,
            ... )
        """
        self._expires_in = _CWT_DEFAULT_EXPIRES_IN
        self._leeway = _CWT_DEFAULT_LEEWAY
        self._cose = COSE(options)
        if not options:
            return

        if "expires_in" in options:
            if not isinstance(options["expires_in"], int):
                raise ValueError("expires_in should be int.")
            self._expires_in = options["expires_in"]
            if self._expires_in <= 0:
                raise ValueError("expires_in should be positive number.")
        if "leeway" in options:
            if not isinstance(options["leeway"], int):
                raise ValueError("leeway should be int.")
            self._leeway = options["leeway"]
            if self._leeway <= 0:
                raise ValueError("leeway should be positive number.")

    @property
    def expires_in(self) -> int:
        """
        The default lifetime in seconds of CWT.
        If `exp` is not found in claims, this value will be used with current time.
        """
        return self._expires_in

    @property
    def leeway(self) -> int:
        """
        The default leeway in seconds for validating ``exp`` and ``nbf``.
        """
        return self._leeway

    def encode_and_mac(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: COSEKey,
        tagged: bool = False,
        recipients: Optional[List[Recipient]] = None,
    ) -> bytes:
        """
        Encode CWT claims and add MAC to it.

        Args:
            claims (Union[Dict[int, Any], bytes]): A CWT claims object or byte string.
            key (COSEKey): A COSE key used to generate a MAC for the claims.
            recipients (List[Recipient]): A list of recipient information structures.
            tagged (bool): An indicator whether the response is wrapped by CWT tag(61)
                or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        self._validate(claims)
        self._set_default_value(claims)
        protected: Dict[int, Any] = {1: key.alg}
        unprotected: Dict[int, Any] = {4: key.kid} if key.kid else {}
        res = self._cose.encode_and_mac(
            protected, unprotected, claims, key, recipients, out="cbor2/CBORTag"
        )
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def encode_and_sign(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: Union[COSEKey, List[COSEKey]],
        tagged: bool = False,
    ) -> bytes:
        """
        Encode CWT claims and sign it.

        Args:
            claims (Union[Dict[int, Any], bytes]): A CWT claims object or byte string.
            key (Union[COSEKey, List[COSEKey]]): A COSE key or a list of the keys used
                to sign claims.
            tagged (bool): An indicator whether the response is wrapped by CWT tag(61)
                or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        self._validate(claims)
        self._set_default_value(claims)
        protected: Dict[int, Any] = {}
        unprotected: Dict[int, Any] = {}
        res = self._cose.encode_and_sign(
            protected, unprotected, claims, key, out="cbor2/CBORTag"
        )
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def encode_and_encrypt(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: COSEKey,
        nonce: bytes,
        tagged: bool = False,
        recipients: Optional[List[Recipient]] = None,
    ) -> bytes:
        """
        Encode CWT claims and encrypt it.

        Args:
            claims (Union[Dict[int, Any], bytes]): CWT claims.
            key (COSEKey): A COSE key used to encrypt the claims.
            nonce (bytes): A nonce for encryption.
            recipients (List[Recipient]): A list of recipient information structures.
            tagged (bool): An indicator whether the response is wrapped by CWT tag(61)
                or not.
        Returns:
            bytes: A byte string of the encoded CWT.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode the claims.
        """
        self._validate(claims)
        self._set_default_value(claims)
        protected: Dict[int, Any] = {1: key.alg}
        unprotected: Dict[int, Any] = {4: key.kid} if key.kid else {}
        unprotected[5] = nonce
        res = self._cose.encode_and_encrypt(
            protected, unprotected, claims, key, nonce, recipients, out="cbor2/CBORTag"
        )
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def decode(
        self, data: bytes, key: Union[COSEKey, List[COSEKey]], no_verify: bool = False
    ) -> Dict[int, Any]:
        """
        Verify and decode CWT.

        Args:
            data (bytes): A byte string of an encoded CWT.
            key (Union[COSEKey, List[COSEKey]]): A COSE key or a list of the keys
                used to verify and decrypt the encoded CWT.
            no_verify (bool): An indicator whether token verification is skiped
                or not.
        Returns:
            bytes: A byte string of the decoded CWT.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the CWT.
            VerifyError: Failed to verify the CWT.
        """
        cwt = self._loads(data)
        if isinstance(cwt, CBORTag) and cwt.tag == CWT.CBOR_TAG:
            cwt = cwt.value
        keys: List[COSEKey] = [key] if isinstance(key, COSEKey) else key
        for k in keys:
            cwt = self._cose.decode(cwt, k)
        if not no_verify:
            self._verify(cwt)
        return cwt

    def _validate(self, claims: Union[Dict[int, Any], bytes]):
        if isinstance(claims, bytes):
            nested = self._loads(claims)
            if not isinstance(nested, CBORTag):
                raise ValueError("A bytes-formatted claims needs CBOR(COSE) Tag.")
            if nested.tag not in [16, 96, 17, 97, 18, 98]:
                raise ValueError(f"Unsupported or unknown CBOR tag({nested.tag}).")
            return
        if -260 in claims and not isinstance(claims[-260], dict):
            raise ValueError("hcert(-260) should be map.")
        if -259 in claims and not isinstance(claims[-259], bytes):
            raise ValueError("EUPHNonce(-259) should be bstr.")
        if -258 in claims and not isinstance(claims[-258], bytes):
            raise ValueError("EATMAROEPrefix(-258) should be bstr.")
        if -257 in claims and not isinstance(claims[-257], list):
            raise ValueError("EAT-FDO(-257) should be array.")
        if 1 in claims and not isinstance(claims[1], str):
            raise ValueError("iss(1) should be str.")
        if 2 in claims and not isinstance(claims[2], str):
            raise ValueError("sub(2) should be str.")
        if 3 in claims and not isinstance(claims[3], str):
            raise ValueError("aud(3) should be str.")
        if 4 in claims and not (
            isinstance(claims[4], int) or isinstance(claims[4], float)
        ):
            raise ValueError("exp(4) should be int or float.")
        if 5 in claims and not (
            isinstance(claims[5], int) or isinstance(claims[5], float)
        ):
            raise ValueError("nbf(5) should be int or float.")
        if 6 in claims and not (
            isinstance(claims[6], int) or isinstance(claims[6], float)
        ):
            raise ValueError("iat(6) should be int or float.")
        if 7 in claims and not isinstance(claims[7], bytes):
            raise ValueError("cti(7) should be bytes.")
        if 8 in claims and not isinstance(claims[8], dict):
            raise ValueError("cnf(7) should be map.")
        return

    def _verify(self, claims: Dict[int, Any]):
        now = timegm(datetime.utcnow().utctimetuple())

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
        """"""
        if isinstance(claims, bytes):
            return
        now = timegm(datetime.utcnow().utctimetuple())
        if 4 not in claims:
            claims[4] = now + self._expires_in
        if 5 not in claims:
            claims[5] = now
        if 6 not in claims:
            claims[6] = now
        return


# export
_cwt = CWT()
encode_and_mac = _cwt.encode_and_mac
encode_and_sign = _cwt.encode_and_sign
encode_and_encrypt = _cwt.encode_and_encrypt
decode = _cwt.decode
