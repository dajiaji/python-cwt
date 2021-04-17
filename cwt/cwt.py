from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag, dumps, loads

from .cose import COSE
from .cose_key import COSEKey


class CWT:
    """
    A CWT (CBOR Web Token) Implementaion.
    """

    CBOR_TAG = 61

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self._cose = COSE(options)

    def encode_and_mac(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: COSEKey,
        iv: Optional[str] = None,
        partial_iv: Optional[str] = None,
        tagged: Optional[bool] = False,
    ) -> bytes:
        """
        Encode CWT claims and add MAC to it.
        """
        self._validate(claims)
        protected: Dict[int, Any] = {1: key.alg}
        unprotected: Dict[int, Any] = {4: key.kid} if key.kid else {}
        res = self._cose.encode_and_mac(
            protected, unprotected, claims, key, out="cbor2/CBORTag"
        )
        if tagged:
            return dumps(CBORTag(CWT.CBOR_TAG, res))
        return dumps(res)

    def encode_and_sign(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: Union[COSEKey, List[COSEKey]],
        tagged: Optional[bool] = False,
    ) -> bytes:
        """
        Encode CWT claims and sign it.
        """
        self._validate(claims)
        protected: Dict[int, Any] = {}
        unprotected: Dict[int, Any] = {}
        res = self._cose.encode_and_sign(
            protected, unprotected, claims, key, out="cbor2/CBORTag"
        )
        if tagged:
            return dumps(CBORTag(CWT.CBOR_TAG, res))
        return dumps(res)

    def encode_and_encrypt(
        self,
        claims: Union[Dict[int, Any], bytes],
        key: COSEKey,
        nonce: bytes,
        tagged: Optional[bool] = False,
    ) -> bytes:
        """
        Encode CWT claims and encrypt it.
        """
        self._validate(claims)
        protected: Dict[int, Any] = {1: key.alg}
        unprotected: Dict[int, Any] = {4: key.kid} if key.kid else {}
        if nonce:
            unprotected[5] = nonce
        res = self._cose.encode_and_encrypt(
            protected, unprotected, claims, key, nonce, out="cbor2/CBORTag"
        )
        if tagged:
            return dumps(CBORTag(CWT.CBOR_TAG, res))
        return dumps(res)

    def decode(self, data: bytes, key: Union[COSEKey, List[COSEKey]]) -> bytes:
        """
        Verify and decode CWT.
        """
        cwt = loads(data)
        if isinstance(cwt, CBORTag) and cwt.tag == CWT.CBOR_TAG:
            cwt = cwt.value
        keys: List[COSEKey] = [key] if isinstance(key, COSEKey) else key
        for k in keys:
            cwt = self._cose.decode(cwt, k)
        return cwt

    def _validate(self, claims: Union[Dict[int, Any], bytes]):
        """"""
        if isinstance(claims, bytes):
            nested = loads(claims)
            if not isinstance(nested, CBORTag):
                raise ValueError("bytes-formatted claims need CBOR(COSE) Tag.")
            if nested.tag not in [16, 96, 17, 97, 18, 98]:
                raise ValueError("Unsupported or unknown CBOR tag.")
            return
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
        return


# export
_cwt = CWT()
encode_and_mac = _cwt.encode_and_mac
encode_and_sign = _cwt.encode_and_sign
encode_and_encrypt = _cwt.encode_and_encrypt
decode = _cwt.decode
