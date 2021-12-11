from typing import Any, Dict, List, Optional, Union

from asn1crypto import pem
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
        self,
        alg_auto_inclusion: bool = False,
        kid_auto_inclusion: bool = False,
        verify_kid: bool = False,
        ca_certs: str = "",
    ):
        if not isinstance(alg_auto_inclusion, bool):
            raise ValueError("alg_auto_inclusion should be bool.")
        self._alg_auto_inclusion = alg_auto_inclusion

        if not isinstance(kid_auto_inclusion, bool):
            raise ValueError("kid_auto_inclusion should be bool.")
        self._kid_auto_inclusion = kid_auto_inclusion

        if not isinstance(verify_kid, bool):
            raise ValueError("verify_kid should be bool.")
        self._verify_kid = verify_kid

        self._ca_certs = []
        if ca_certs:
            if not isinstance(ca_certs, str):
                raise ValueError("ca_certs should be str.")
            self._trust_roots: List[bytes] = []
            with open(ca_certs, "rb") as f:
                for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
                    self._ca_certs.append(der_bytes)

    @classmethod
    def new(
        cls,
        alg_auto_inclusion: bool = False,
        kid_auto_inclusion: bool = False,
        verify_kid: bool = False,
        ca_certs: str = "",
    ):
        """
        Constructor.

        Args:
            alg_auto_inclusion(bool): The indicator whether ``alg`` parameter is included
                in a proper header bucket automatically or not.
            kid_auto_inclusion(bool): The indicator whether ``kid`` parameter is included
                in a proper header bucket automatically or not.
            verify_kid(bool): The indicator whether ``kid`` verification is mandatory or
                not.
            ca_certs(str): The path to a file which contains a concatenated list
                of trusted root certificates. You should specify private CA
                certificates in your target system. There should be no need to
                use the public CA certificates for the Web PKI.
        """
        return cls(alg_auto_inclusion, kid_auto_inclusion, verify_kid, ca_certs)

    @property
    def alg_auto_inclusion(self) -> bool:
        """
        If this property is True, an encode_and_*() function will automatically
        set the ``alg`` parameter in the header from the COSEKey argument.
        """
        return self._alg_auto_inclusion

    @alg_auto_inclusion.setter
    def alg_auto_inclusion(self, alg_auto_inclusion: bool):
        self._alg_auto_inclusion = alg_auto_inclusion
        return

    @property
    def kid_auto_inclusion(self) -> bool:
        """
        If this property is True, an encode_and_*() function will automatically
        set the ``kid`` parameter in the header from the COSEKey argument.
        """
        return self._kid_auto_inclusion

    @kid_auto_inclusion.setter
    def kid_auto_inclusion(self, kid_auto_inclusion: bool):
        self._kid_auto_inclusion = kid_auto_inclusion
        return

    @property
    def verify_kid(self) -> bool:
        """
        If this property is True, the decode() function will perform the verification
        and decoding process only if the ``kid`` of the COSE data to be decoded and
        one of the ``kid`` s in the key list given as an argument match exact.
        """
        return self._verify_kid

    @verify_kid.setter
    def verify_kid(self, verify_kid: bool):
        self._verify_kid = verify_kid
        return

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
        p: Union[Dict[int, Any], bytes] = to_cose_header(protected) if not isinstance(protected, bytes) else protected
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
                b_protected = self._dumps(p)
            if self._kid_auto_inclusion and key.kid:
                u[4] = key.kid
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
            raise NotImplementedError("Algorithms other than direct are not supported for recipients.")

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
            key (Optional[COSEKeyInterface]): A signing key for single signer
                cases. When the ``signers`` parameter is set, this ``key`` will
                be ignored and should not be set.
            protected (Optional[Union[dict, bytes]]): Parameters that are to be
                cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically
                protected.
            signers (List[Signer]): A list of signer information objects for
                multiple signer cases.
            external_aad(bytes): External additional authenticated data supplied
                by application.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If
                ``"cbor2/CBORTag"`` is specified. This function will return encoded
                data as `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s
                ``CBORTag`` object. If any other value is specified, it will return
                encoded data as bytes.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a
                cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """
        p: Union[Dict[int, Any], bytes] = to_cose_header(protected) if not isinstance(protected, bytes) else protected
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
            protected (Optional[Union[dict, bytes]]): Parameters that are to be
                cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically
                protected.
            nonce (bytes): A nonce for encryption.
            recipients (Optional[List[RecipientInterface]]): A list of recipient
                information structures.
            external_aad(bytes): External additional authenticated data supplied
                by application.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If
                ``"cbor2/CBORTag"`` is specified. This function will return encoded
                data as `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s
                ``CBORTag`` object. If any other value is specified, it will return
                encoded data as bytes.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a
                cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """
        p: Union[Dict[int, Any], bytes] = to_cose_header(protected) if not isinstance(protected, bytes) else protected
        u = to_cose_header(unprotected)

        ctx = "Encrypt0" if not recipients else "Encrypt"

        if not nonce:
            try:
                nonce = key.generate_nonce()
            except NotImplementedError:
                raise ValueError("Nonce generation is not supported for the key. Set a nonce explicitly.")

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
            raise NotImplementedError("Algorithms other than direct are not supported for recipients.")
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
        keys: Union[COSEKeyInterface, List[COSEKeyInterface]],
        context: Optional[Union[Dict[str, Any], List[Any]]] = None,
        external_aad: bytes = b"",
    ) -> bytes:

        """
        Verifies and decodes COSE data.

        Args:
            data (Union[bytes, CBORTag]): A byte string or cbor2.CBORTag of an
                encoded data.
            keys (Union[COSEKeyInterface, List[COSEKeyInterface]]): COSE key(s)
                to verify and decrypt the encoded data.
            context (Optional[Union[Dict[str, Any], List[Any]]]): A context information
                structure for key deriviation functions.
            external_aad(bytes): External additional authenticated data supplied by
                application.
        Returns:
            bytes: A byte string of decoded payload.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode data.
            VerifyError: Failed to verify data.
        """
        if isinstance(data, bytes):
            data = self._loads(data)
        if not isinstance(data, CBORTag):
            raise ValueError("Invalid COSE format.")

        if not isinstance(keys, list):
            if not isinstance(keys, COSEKeyInterface):
                raise ValueError("key in keys should have COSEKeyInterface.")
            keys = [keys]

        if data.tag == 16:
            keys = self._filter_by_key_ops(keys, 4)
            if not isinstance(data.value, list) or len(data.value) != 3:
                raise ValueError("Invalid Encrypt0 format.")
        elif data.tag == 96:
            keys = self._filter_by_key_ops(keys, 4)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Encrypt format.")
        elif data.tag == 17:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid MAC0 format.")
        elif data.tag == 97:
            keys = self._filter_by_key_ops(keys, 10)
            if not isinstance(data.value, list) or len(data.value) != 5:
                raise ValueError("Invalid MAC format.")
        elif data.tag == 18:
            keys = self._filter_by_key_ops(keys, 2)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature1 format.")
        elif data.tag == 98:
            keys = self._filter_by_key_ops(keys, 2)
            if not isinstance(data.value, list) or len(data.value) != 4:
                raise ValueError("Invalid Signature format.")
        else:
            raise ValueError(f"Unsupported or unknown CBOR tag({data.tag}).")

        protected = self._loads(data.value[0]) if data.value[0] else b""
        unprotected = data.value[1]
        if not isinstance(unprotected, dict):
            raise ValueError("unprotected header should be dict.")
        alg = self._get_alg(protected)

        err: Exception = ValueError("key is not found.")

        # Encrypt0
        if data.tag == 16:
            kid = self._get_kid(protected, unprotected)
            aad = self._dumps(["Encrypt0", data.value[0], external_aad])
            nonce = unprotected.get(5, None)
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        return k.decrypt(data.value[2], nonce, aad)
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    return k.decrypt(data.value[2], nonce, aad)
                except Exception as e:
                    err = e
            raise err

        # Encrypt
        if data.tag == 96:
            aad = self._dumps(["Encrypt", data.value[0], external_aad])
            nonce = unprotected.get(5, None)
            rs = Recipients.from_list(data.value[3], self._verify_kid)
            enc_key = rs.extract(keys, context, alg)
            return enc_key.decrypt(data.value[2], nonce, aad)

        # MAC0
        if data.tag == 17:
            kid = self._get_kid(protected, unprotected)
            msg = self._dumps(["MAC0", data.value[0], external_aad, data.value[2]])
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        k.verify(msg, data.value[3])
                        return data.value[2]
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    k.verify(msg, data.value[3])
                    return data.value[2]
                except Exception as e:
                    err = e
            raise err

        # MAC
        if data.tag == 97:
            to_be_maced = self._dumps(["MAC", data.value[0], external_aad, data.value[2]])
            rs = Recipients.from_list(data.value[4], self._verify_kid)
            mac_auth_key = rs.extract(keys, context, alg)
            mac_auth_key.verify(to_be_maced, data.value[3])
            return data.value[2]

        # Signature1
        if data.tag == 18:
            kid = self._get_kid(protected, unprotected)
            to_be_signed = self._dumps(["Signature1", data.value[0], external_aad, data.value[2]])
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        if self._ca_certs:
                            k.validate_certificate(self._ca_certs)
                        k.verify(to_be_signed, data.value[3])
                        return data.value[2]
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    if self._ca_certs:
                        k.validate_certificate(self._ca_certs)
                    k.verify(to_be_signed, data.value[3])
                    return data.value[2]
                except Exception as e:
                    err = e
            raise err

        # Signature
        # if data.tag == 98:
        sigs = data.value[3]
        if not isinstance(sigs, list):
            raise ValueError("Invalid Signature format.")
        for sig in sigs:
            if not isinstance(sig, list) or len(sig) != 3:
                raise ValueError("Invalid Signature format.")

            protected = self._loads(sig[0]) if sig[0] else b""
            unprotected = sig[1]
            if not isinstance(unprotected, dict):
                raise ValueError("unprotected header in signature structure should be dict.")
            kid = self._get_kid(protected, unprotected)
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        to_be_signed = self._dumps(
                            [
                                "Signature",
                                data.value[0],
                                sig[0],
                                external_aad,
                                data.value[2],
                            ]
                        )
                        k.verify(to_be_signed, sig[2])
                        return data.value[2]
                    except Exception as e:
                        err = e
                continue
            for _, k in enumerate(keys):
                try:
                    to_be_signed = self._dumps(
                        [
                            "Signature",
                            data.value[0],
                            sig[0],
                            external_aad,
                            data.value[2],
                        ]
                    )
                    k.verify(to_be_signed, sig[2])
                    return data.value[2]
                except Exception as e:
                    err = e
        raise err

    def _filter_by_key_ops(self, keys: List[COSEKeyInterface], op: int) -> List[COSEKeyInterface]:
        res: List[COSEKeyInterface] = []
        for k in keys:
            if op in k.key_ops:
                res.append(k)
        if len(res) == 0:
            res = keys
        return res

    def _get_alg(self, protected: Any) -> int:
        return protected[1] if isinstance(protected, dict) and 1 in protected else 0

    def _get_kid(self, protected: Any, unprotected: dict) -> bytes:
        kid = b""
        if isinstance(protected, dict) and 4 in protected:
            kid = protected[4]
        elif 4 in unprotected:
            kid = unprotected[4]
        elif self._verify_kid:
            raise ValueError("kid should be specified.")
        return kid
