from typing import Any, Dict, List, Optional, Union

from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .const import COSE_ALGORITHMS_RECIPIENT
from .cose_key_interface import COSEKeyInterface
from .recipient_interface import RecipientInterface
from .recipients import Recipients
from .signer import Signer
from .utils import to_cose_header


class COSE(CBORProcessor):
    """
    A COSE (CBOR Object Signing and Encryption) Implementaion built on top of
    `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_.
    """

    def __init__(
        self, alg_auto_inclusion: int = False, kid_auto_inclusion: int = False
    ):
        if not isinstance(alg_auto_inclusion, bool):
            raise ValueError("alg_auto_inclusion should be bool.")
        self._alg_auto_inclusion = alg_auto_inclusion

        if not isinstance(kid_auto_inclusion, bool):
            raise ValueError("kid_auto_inclusion should be bool.")
        self._kid_auto_inclusion = kid_auto_inclusion

    @classmethod
    def new(cls, alg_auto_inclusion: int = False, kid_auto_inclusion: int = False):
        """
        Constructor.

        Args:
            alg_auto_inclusion(bool): The indicator whether ``alg`` parameter is included
                in a proper header bucket automatically or not.
            kid_auto_inclusion(bool): The indicator whether ``kid`` parameter is included
                in a proper header bucket automatically or not.
        """
        return cls(alg_auto_inclusion, kid_auto_inclusion)

    def encode_and_mac(
        self,
        payload: bytes,
        key: COSEKeyInterface,
        protected: Optional[Union[dict, bytes]] = None,
        unprotected: Optional[dict] = None,
        recipients: Optional[List[RecipientInterface]] = None,
        external_aad: bytes = b"",
        out: str = "",
    ) -> Union[bytes, CBORTag]:
        """
        Encodes data with MAC.

        Args:
            payload (bytes): A content to be MACed.
            key (COSEKeyInterface): A COSE key as a MAC Authentication key.
            protected (Optional[Union[dict, bytes]]): Parameters that are to be cryptographically
                protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            recipients (Optional[List[RecipientInterface]]): A list of recipient information structures.
            external_aad(bytes): External additional authenticated data supplied by application.
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
        p: Union[Dict[int, Any], bytes] = (
            to_cose_header(protected) if not isinstance(protected, bytes) else protected
        )
        u = to_cose_header(unprotected)

        ctx = "MAC0" if not recipients else "MAC"
        b_protected = b""

        # MAC0
        if not recipients:
            if isinstance(p, bytes):
                b_protected = p
            else:
                if self._alg_auto_inclusion:
                    p[1] = key.alg
                if self._kid_auto_inclusion and key.kid:
                    u[4] = key.kid
                b_protected = self._dumps(p)
            mac_structure = [ctx, b_protected, external_aad, payload]
            tag = key.sign(self._dumps(mac_structure))
            res = CBORTag(17, [b_protected, u, payload, tag])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # MAC
        recs = []
        for rec in recipients:
            recs.append(rec.to_list())
        if recipients[0].alg in COSE_ALGORITHMS_RECIPIENT.values():
            if not isinstance(p, bytes):
                if self._alg_auto_inclusion:
                    p[1] = key.alg
                if self._kid_auto_inclusion and key.kid:
                    u[4] = key.kid
        else:
            raise NotImplementedError(
                "Algorithms other than direct are not supported for recipients."
            )

        if isinstance(p, bytes):
            b_protected = p
        else:
            b_protected = self._dumps(p) if p else b""
        mac_structure = [ctx, b_protected, external_aad, payload]
        tag = key.sign(self._dumps(mac_structure))
        cose_mac: List[Any] = [b_protected, u, payload, tag]
        cose_mac.append(recs)
        res = CBORTag(97, cose_mac)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def encode_and_sign(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface] = None,
        protected: Optional[Union[dict, bytes]] = None,
        unprotected: Optional[dict] = None,
        signers: List[Signer] = [],
        external_aad: bytes = b"",
        out: str = "",
    ) -> Union[bytes, CBORTag]:
        """
        Encodes data with signing.

        Args:
            payload (bytes): A content to be signed.
            key (COSEKeyInterface): A signing key for single signer cases. When the ``signers``
                parameter is set, this ``key`` will be ignored and should not be set.
            protected (Optional[Union[dict, bytes]]): Parameters that are to be cryptographically
                protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            signers (Optional[List[Signer]]): A list of signer information objects for multiple
                signer cases.
            external_aad(bytes): External additional authenticated data supplied by application.
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
        p: Union[Dict[int, Any], bytes] = (
            to_cose_header(protected) if not isinstance(protected, bytes) else protected
        )
        u = to_cose_header(unprotected)

        ctx = "Signature" if signers else "Signature1"
        if not signers and key is not None:
            if isinstance(p, dict) and self._alg_auto_inclusion:
                p[1] = key.alg
            if self._kid_auto_inclusion and key.kid:
                u[4] = key.kid

        b_protected = b""
        if isinstance(p, bytes):
            b_protected = p
        else:
            b_protected = self._dumps(p) if p else b""

        # Signature1
        if not signers and key is not None:
            sig_structure = [ctx, b_protected, external_aad, payload]
            sig = key.sign(self._dumps(sig_structure))
            res = CBORTag(18, [b_protected, u, payload, sig])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Signature
        sigs = []
        for s in signers:
            sig_structure = [ctx, b_protected, s.protected, external_aad, payload]
            s.sign(self._dumps(sig_structure))
            sigs.append([s.protected, s.unprotected, s.signature])
        res = CBORTag(98, [b_protected, u, payload, sigs])
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def encode_and_encrypt(
        self,
        payload: bytes,
        key: COSEKeyInterface,
        protected: Optional[Union[dict, bytes]] = None,
        unprotected: Optional[dict] = None,
        nonce: bytes = b"",
        recipients: Optional[List[RecipientInterface]] = None,
        external_aad: bytes = b"",
        out: str = "",
    ) -> bytes:
        """
        Encodes data with encryption.

        Args:
            payload (bytes): A content to be encrypted.
            key (COSEKeyInterface): A COSE key as an encryption key.
            protected (Optional[Union[dict, bytes]]): Parameters that are to be cryptographically
                protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            nonce (bytes): A nonce for encryption.
            recipients (Optional[List[RecipientInterface]]): A list of recipient information structures.
            external_aad(bytes): External additional authenticated data supplied by application.
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
        p: Union[Dict[int, Any], bytes] = (
            to_cose_header(protected) if not isinstance(protected, bytes) else protected
        )
        u = to_cose_header(unprotected)

        ctx = "Encrypt0" if not recipients else "Encrypt"

        if not nonce:
            try:
                nonce = key.generate_nonce()
            except NotImplementedError:
                raise ValueError(
                    "Nonce generation is not supported for the key. Set a nonce explicitly."
                )

        # Encrypt0
        if not recipients:
            if isinstance(p, bytes):
                b_protected = p
            else:
                if self._alg_auto_inclusion:
                    p[1] = key.alg
                b_protected = self._dumps(p) if p else b""
            if self._kid_auto_inclusion and key.kid:
                u[4] = key.kid
            u[5] = nonce
            enc_structure = [ctx, b_protected, external_aad]
            aad = self._dumps(enc_structure)
            ciphertext = key.encrypt(payload, nonce, aad)
            res = CBORTag(16, [b_protected, u, ciphertext])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Encrypt
        recs = []
        for rec in recipients:
            recs.append(rec.to_list())
        if recipients[0].alg in COSE_ALGORITHMS_RECIPIENT.values():
            if not isinstance(p, bytes) and self._alg_auto_inclusion:
                p[1] = key.alg
            if self._kid_auto_inclusion and key.kid:
                u[4] = key.kid
            u[5] = nonce
        else:
            raise NotImplementedError(
                "Algorithms other than direct are not supported for recipients."
            )
        if isinstance(p, bytes):
            b_protected = p
        else:
            b_protected = self._dumps(p) if p else b""
        enc_structure = [ctx, b_protected, external_aad]
        aad = self._dumps(enc_structure)
        ciphertext = key.encrypt(payload, nonce, aad)
        cose_enc: List[Any] = [b_protected, u, ciphertext]
        cose_enc.append(recs)
        res = CBORTag(96, cose_enc)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def decode(
        self,
        data: Union[bytes, CBORTag],
        key: Optional[Union[COSEKeyInterface, List[COSEKeyInterface]]] = None,
        context: Optional[Union[Dict[str, Any], List[Any]]] = None,
        materials: Optional[List[dict]] = None,
        external_aad: bytes = b"",
    ) -> bytes:
        """
        Verifies and decodes COSE data.

        Args:
            data (Union[bytes, CBORTag]): A byte string or cbor2.CBORTag of an
                encoded data.
            key (Optional[Union[COSEKeyInterface, List[COSEKeyInterface]]]): A COSE
                key to verify and decrypt the encoded data.
            context (Optional[Union[Dict[str, Any], List[Any]]]): A context information
                structure for key deriviation functions.
            materials (Optional[List[dict]]): A list of key materials to be used to
                derive an encryption key.
            external_aad(bytes): External additional authenticated data supplied by
                application.
        Returns:
            bytes: A byte string of decoded payload.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode data.
            VerifyError: Failed to verify data.
        """
        if key is None and materials is None:
            raise ValueError("Either key or materials should be specified.")
        if isinstance(data, bytes):
            data = self._loads(data)
        if not isinstance(data, CBORTag):
            raise ValueError("Invalid COSE format.")

        keys: List[COSEKeyInterface] = []
        if key:
            keys = key if isinstance(key, list) else [key]

        # Encrypt0
        if data.tag == 16:
            keys = self._filter_by_key_ops(keys, 4)
            if not isinstance(data.value, list) or len(data.value) != 3:
                raise ValueError("Invalid Encrypt0 format.")

            aad = self._dumps(["Encrypt0", data.value[0], external_aad])
            unprotected = data.value[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header should be dict.")
            nonce = unprotected.get(5, None)
            k = self._get_key(keys, unprotected)
            if not k:
                raise ValueError("key is not specified.")
            return k.decrypt(data.value[2], nonce, aad)

        # Encrypt
        if data.tag == 96:
            if keys:
                keys = self._filter_by_key_ops(keys, 4)
                if not isinstance(data.value, list) or len(data.value) != 4:
                    raise ValueError("Invalid Encrypt format.")

            aad = self._dumps(["Encrypt", data.value[0], external_aad])
            alg = 0
            if data.value[0]:
                protected = self._loads(data.value[0])
                alg = (
                    protected[1]
                    if isinstance(protected, dict) and 1 in protected
                    else 0
                )
            unprotected = data.value[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header should be dict.")
            nonce = unprotected.get(5, None)
            rs = Recipients.from_list(data.value[3])
            enc_key = rs.extract_key(keys, context, materials, alg)
            return enc_key.decrypt(data.value[2], nonce, aad)

        # MAC0
        if data.tag == 17:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid MAC0 format.")

            msg = self._dumps(["MAC0", data.value[0], external_aad, data.value[2]])
            k = self._get_key(keys, data.value[1])
            if not k:
                raise ValueError("key is not specified.")
            k.verify(msg, data.value[3])
            return data.value[2]

        # MAC
        if data.tag == 97:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 5:
                raise ValueError("Invalid MAC format.")
            to_be_maced = self._dumps(
                ["MAC", data.value[0], external_aad, data.value[2]]
            )
            alg = 0
            if data.value[0]:
                protected = self._loads(data.value[0])
                alg = (
                    protected[1]
                    if isinstance(protected, dict) and 1 in protected
                    else 0
                )
            rs = Recipients.from_list(data.value[4])
            mac_auth_key = rs.extract_key(keys, context, materials, alg)
            mac_auth_key.verify(to_be_maced, data.value[3])
            return data.value[2]

        # Signature1
        if data.tag == 18:
            keys = self._filter_by_key_ops(keys, 2)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature1 format.")

            to_be_signed = self._dumps(
                ["Signature1", data.value[0], external_aad, data.value[2]]
            )
            k = self._get_key(keys, data.value[1])
            if not k:
                raise ValueError("key is not specified.")
            k.verify(to_be_signed, data.value[3])
            return data.value[2]

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
                    ["Signature", data.value[0], sig[0], external_aad, data.value[2]]
                )
                k.verify(to_be_signed, sig[2])
                return data.value[2]
            raise ValueError("Verification key not found.")
        raise ValueError(f"Unsupported or unknown CBOR tag({data.tag}).")

    def _get_key(
        self, keys: List[COSEKeyInterface], unprotected: Dict[int, Any]
    ) -> Union[COSEKeyInterface, None]:
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

    def _filter_by_key_ops(
        self, keys: List[COSEKeyInterface], op: int
    ) -> List[COSEKeyInterface]:
        res: List[COSEKeyInterface] = []
        for k in keys:
            if op in k.key_ops:
                res.append(k)
        if len(res) == 0:
            res = keys
        return res
