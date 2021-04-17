from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag, dumps, loads

from .cose_key import COSEKey
from .exceptions import InvalidSignature


class COSE:
    """
    A COSE (CBOR Object Signing and Encryption) Implementaion.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self._options = options

    def encode_and_mac(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: COSEKey,
        out: Optional[str] = None,
    ) -> Union[bytes, CBORTag]:

        b_protected = dumps(protected)
        b_payload = dumps(payload)
        mac_structure = ["MAC0", b_protected, b"", b_payload]
        tag = key.sign(dumps(mac_structure))
        res = CBORTag(17, [b_protected, unprotected, b_payload, tag])
        return res if out == "cbor2/CBORTag" else dumps(res)

    def encode_and_sign(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: Union[COSEKey, List[COSEKey]],
        out: Optional[str] = None,
    ) -> Union[bytes, CBORTag]:

        ctx = "Signature" if not isinstance(key, COSEKey) else "Signature1"
        if isinstance(key, COSEKey):
            protected[1] = key.alg
            unprotected[4] = key.kid if key.kid else {}

        b_protected = dumps(protected) if protected else b""
        b_payload = dumps(payload)

        # Signature1
        if isinstance(key, COSEKey):
            sig_structure = [ctx, b_protected, b"", b_payload]
            sig = key.sign(dumps(sig_structure))
            res = CBORTag(18, [b_protected, unprotected, b_payload, sig])
            return res if out == "cbor2/CBORTag" else dumps(res)

        # Signature
        sigs = []
        for k in key:
            p_header = dumps({1: k.alg})
            u_header = dumps({4: k.kid} if k.kid else {})
            sig_structure = [ctx, b_protected, p_header, b"", b_payload]
            sig = k.sign(dumps(sig_structure))
            sigs.append(dumps([p_header, u_header, sig]))
        res = CBORTag(18, [b_protected, unprotected, b_payload, sigs])
        return res if out == "cbor2/CBORTag" else dumps(res)

    def encode_and_encrypt(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: COSEKey,
        nonce: bytes = b"",
        out: str = "",
    ) -> bytes:

        b_protected = dumps(protected)
        b_payload = dumps(payload)
        aad = dumps(["Encrypt0", b_protected, b""])
        ciphertext = key.encrypt(b_payload, nonce, aad)
        res = CBORTag(16, [b_protected, unprotected, ciphertext])
        return res if out == "cbor2/CBORTag" else dumps(res)

    def decode(self, data: Union[bytes, CBORTag], key: COSEKey) -> Dict[int, Any]:

        if isinstance(data, bytes):
            data = loads(data)
        if not isinstance(data, CBORTag):
            raise ValueError("Invalid COSE format.")

        # Encrypt0
        if data.tag == 16:
            if not isinstance(data.value, list) or len(data.value) != 3:
                raise ValueError("Invalid Encrypt0 format.")

            aad = dumps(["Encrypt0", data.value[0], b""])
            unprotected = data.value[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header should be dict.")
            nonce = unprotected.get(5, None)
            payload = key.decrypt(data.value[2], nonce, aad)
            return loads(payload)

        # Encrypt
        if data.tag == 96:
            raise NotImplementedError()

        # MAC0
        if data.tag == 17:
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid MAP0 format.")

            msg = dumps(["MAC0", data.value[0], b"", data.value[2]])
            try:
                key.verify(msg, data.value[3])
            except InvalidSignature:
                raise
            return loads(data.value[2])

        # MAC
        if data.tag == 97:
            raise NotImplementedError()

        # Signature1
        if data.tag == 18:
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature1 format.")

            msg = dumps(["Signature1", data.value[0], b"", data.value[2]])
            try:
                key.verify(msg, data.value[3])
            except InvalidSignature:
                raise
            return loads(data.value[2])

        # Signature
        if data.tag == 98:
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature format.")
            sigs = data.value[3]
            if not isinstance(sigs, list):
                raise ValueError("Invalid Signature format.")

            msg = dumps(["Signature", data.value[0], b"", data.value[2]])
            raise NotImplementedError()

        raise ValueError("Unsupported or unknown tag: %d" % data.tag)
