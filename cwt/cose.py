from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .cose_key import COSEKey
from .recipient import Recipient, RecipientsBuilder


class COSE(CBORProcessor):
    """
    A COSE (CBOR Object Signing and Encryption) Implementaion built on top of
    `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_.

    ``cwt.cose_key`` is a global object of this class initialized with default settings.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Constructor.

        At the current implementation, any ``options`` will be ignored.
        """
        self._options = options
        self._recipients_builder = RecipientsBuilder()

    def encode_and_mac(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: COSEKey,
        recipients: Optional[List[Recipient]] = None,
        out: str = "",
    ) -> Union[bytes, CBORTag]:
        """
        Encodes data with MAC.

        Args:
            protected (Dict[int, Any]): Parameters that are to be cryptographically
                protected.
            unprotected (Dict[int, Any]): Parameters that are not cryptographically
                protected.
            payload (Union[Dict[int, Any], bytes]): A content to be MACed.
            key (COSEKey): A COSE key as a MAC Authentication key.
            recipients (Optional[List[Recipient]]): A list of recipient information structures.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If ``"cbor2/CBORTag"``
                is specified. This function will return encoded data as
                `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s ``CBORTag`` object.
                If any other value is specified, it will return encoded data as bytes.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """

        ctx = "MAC0" if not recipients else "MAC"

        # MAC0
        if not recipients:
            protected[1] = key.alg
            if key.kid:
                unprotected[4] = key.kid
            b_protected = self._dumps(protected)
            b_payload = self._dumps(payload)
            mac_structure = [ctx, b_protected, b"", b_payload]
            tag = key.sign(self._dumps(mac_structure))
            res = CBORTag(17, [b_protected, unprotected, b_payload, tag])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # MAC
        b_protected = self._dumps(protected) if protected else b""
        b_payload = self._dumps(payload)
        mac_structure = [ctx, b_protected, b"", b_payload]
        tag = key.sign(self._dumps(mac_structure))
        cose_mac: List[Any] = [b_protected, unprotected, b_payload, tag]
        recs = []
        for rec in recipients:
            recs.append(rec.to_list())
        cose_mac.append(recs)
        res = CBORTag(97, cose_mac)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def encode_and_sign(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: Union[COSEKey, List[COSEKey]],
        out: str = "",
    ) -> Union[bytes, CBORTag]:
        """
        Encodes data with signing.

        Args:
            protected (Dict[int, Any]): Parameters that are to be cryptographically
                protected.
            unprotected (Dict[int, Any]): Parameters that are not cryptographically
                protected.
            payload (Union[Dict[int, Any], bytes]): A content to be signed.
            key (Union[COSEKey, List[COSEKey]]): One or more COSE keys as signing keys.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If ``"cbor2/CBORTag"``
                is specified. This function will return encoded data as
                `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s ``CBORTag`` object.
                If any other value is specified, it will return encoded data as bytes.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """

        ctx = "Signature" if not isinstance(key, COSEKey) else "Signature1"
        if isinstance(key, COSEKey):
            protected[1] = key.alg
            if key.kid:
                unprotected[4] = key.kid

        b_protected = self._dumps(protected) if protected else b""
        b_payload = self._dumps(payload)

        # Signature1
        if isinstance(key, COSEKey):
            sig_structure = [ctx, b_protected, b"", b_payload]
            sig = key.sign(self._dumps(sig_structure))
            res = CBORTag(18, [b_protected, unprotected, b_payload, sig])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Signature
        sigs = []
        for k in key:
            p_header = self._dumps({1: k.alg})
            u_header = {4: k.kid} if k.kid else {}
            sig_structure = [ctx, b_protected, p_header, b"", b_payload]
            sig = k.sign(self._dumps(sig_structure))
            sigs.append([p_header, u_header, sig])
        res = CBORTag(98, [b_protected, unprotected, b_payload, sigs])
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def encode_and_encrypt(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        payload: Union[Dict[int, Any], bytes],
        key: COSEKey,
        nonce: bytes = b"",
        recipients: Optional[List[Recipient]] = None,
        out: str = "",
    ) -> bytes:
        """
        Encodes data with encryption.

        Args:
            protected (Dict[int, Any]): Parameters that are to be cryptographically
                protected.
            unprotected (Dict[int, Any]): Parameters that are not cryptographically
                protected.
            payload (Union[Dict[int, Any], bytes]): A content to be encrypted.
            key (COSEKey): A COSE key as an encryption key.
            nonce (bytes): A nonce for encryption.
            recipients (Optional[List[Recipient]]): A list of recipient information structures.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If ``"cbor2/CBORTag"``
                is specified. This function will return encoded data as
                `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s ``CBORTag`` object.
                If any other value is specified, it will return encoded data as bytes.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """

        ctx = "Encrypt0" if not recipients else "Encrypt"

        # Encrypt0
        if not recipients:
            b_protected = self._dumps(protected) if protected else b""
            b_payload = self._dumps(payload)
            enc_structure = [ctx, b_protected, b""]
            aad = self._dumps(enc_structure)
            ciphertext = key.encrypt(b_payload, nonce, aad)
            res = CBORTag(16, [b_protected, unprotected, ciphertext])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Encrypt
        b_protected = self._dumps(protected) if protected else b""
        b_payload = self._dumps(payload)
        enc_structure = [ctx, b_protected, b""]
        aad = self._dumps(enc_structure)
        ciphertext = key.encrypt(b_payload, nonce, aad)
        cose_enc: List[Any] = [b_protected, unprotected, ciphertext]
        recs = []
        for rec in recipients:
            recs.append(rec.to_list())
        cose_enc.append(recs)
        res = CBORTag(96, cose_enc)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def decode(
        self, data: Union[bytes, CBORTag], key: Union[COSEKey, List[COSEKey]]
    ) -> Dict[int, Any]:
        """
        Verifies and decodes COSE data.

        Args:
            data (Union[bytes, CBORTag]): A byte string or cbor2.CBORTag of an
                encoded data.
            key (COSEKey): A COSE key to verify and decrypt the encoded data.
        Returns:
            Dict[int, Any]: A decoded CBOR-like object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode data.
            VerifyError: Failed to verify data.
        """
        if isinstance(data, bytes):
            data = self._loads(data)
        if not isinstance(data, CBORTag):
            raise ValueError("Invalid COSE format.")

        keys: List[COSEKey] = key if isinstance(key, list) else [key]

        # Encrypt0
        if data.tag == 16:
            keys = self._filter_by_key_ops(keys, 4)
            if not isinstance(data.value, list) or len(data.value) != 3:
                raise ValueError("Invalid Encrypt0 format.")

            aad = self._dumps(["Encrypt0", data.value[0], b""])
            unprotected = data.value[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header should be dict.")
            nonce = unprotected.get(5, None)
            k = self._get_key(keys, unprotected)
            if not k:
                raise ValueError("key is not specified.")
            payload = k.decrypt(data.value[2], nonce, aad)
            return self._loads(payload)

        # Encrypt
        if data.tag == 96:
            keys = self._filter_by_key_ops(keys, 4)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Encrypt format.")

            aad = self._dumps(["Encrypt", data.value[0], b""])
            unprotected = data.value[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header should be dict.")
            nonce = unprotected.get(5, None)
            recipients = self._recipients_builder.from_list(data.value[3])
            enc_key = recipients.derive_key(keys)
            payload = enc_key.decrypt(data.value[2], nonce, aad)
            return self._loads(payload)

        # MAC0
        if data.tag == 17:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid MAC0 format.")

            msg = self._dumps(["MAC0", data.value[0], b"", data.value[2]])
            k = self._get_key(keys, data.value[1])
            if not k:
                raise ValueError("key is not specified.")
            k.verify(msg, data.value[3])
            return self._loads(data.value[2])

        # MAC
        if data.tag == 97:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 5:
                raise ValueError("Invalid MAC format.")
            to_be_maced = self._dumps(["MAC", data.value[0], b"", data.value[2]])
            recipients = self._recipients_builder.from_list(data.value[4])
            mac_auth_key = recipients.derive_key(keys)
            mac_auth_key.verify(to_be_maced, data.value[3])
            return self._loads(data.value[2])

        # Signature1
        if data.tag == 18:
            keys = self._filter_by_key_ops(keys, 2)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature1 format.")

            to_be_signed = self._dumps(
                ["Signature1", data.value[0], b"", data.value[2]]
            )
            k = self._get_key(keys, data.value[1])
            if not k:
                raise ValueError("key is not specified.")
            k.verify(to_be_signed, data.value[3])
            return self._loads(data.value[2])

        # Signature
        if data.tag == 98:
            keys = self._filter_by_key_ops(keys, 2)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature format.")
            sigs = data.value[3]
            if not isinstance(sigs, list):
                raise ValueError("Invalid Signature format.")
            for sig in sigs:
                if not isinstance(sig, list) or len(sig) != 3:
                    raise ValueError("Invalid Signature format.")
                k = self._get_key(keys, sig[1])
                if not k:
                    continue
                to_be_signed = self._dumps(
                    ["Signature", data.value[0], sig[0], b"", data.value[2]]
                )
                k.verify(to_be_signed, sig[2])
                return self._loads(data.value[2])
            raise ValueError("Verification key not found.")
        raise ValueError(f"Unsupported or unknown CBOR tag({data.tag}).")

    def _get_key(
        self, keys: List[COSEKey], unprotected: Dict[int, Any]
    ) -> Union[COSEKey, None]:
        if len(keys) == 1:
            if 4 in unprotected and keys[0].kid:
                if unprotected[4] != keys[0].kid:
                    return None
            return keys[0]
        if 4 not in unprotected:
            return None
        for k in keys:
            if k.kid == unprotected[4]:
                return k
        return None

    def _filter_by_key_ops(self, keys: List[COSEKey], op: int) -> List[COSEKey]:
        res: List[COSEKey] = []
        for k in keys:
            if op in k.key_ops:
                res.append(k)
        if len(res) == 0:
            res = keys
        return res
