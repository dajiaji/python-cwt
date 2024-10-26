from typing import Any, Dict, List, Optional, Tuple, Union

from asn1crypto import pem
from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .const import (
    COSE_ALGORITHMS_CEK,
    COSE_ALGORITHMS_CEK_NON_AEAD,
    COSE_ALGORITHMS_CKDM,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT,
    COSE_ALGORITHMS_HPKE,
    COSE_ALGORITHMS_KEY_WRAP,
    COSE_ALGORITHMS_MAC,
    COSE_ALGORITHMS_RECIPIENT,
    COSE_ALGORITHMS_SIGNATURE,
)
from .cose_key_interface import COSEKeyInterface
from .recipient_algs.hpke import HPKE
from .recipient_interface import RecipientInterface
from .recipients import Recipients
from .signer import Signer
from .utils import sort_keys_for_deterministic_encoding, to_cose_header


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
        deterministic_header: bool = False,
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

        if not isinstance(deterministic_header, bool):
            raise ValueError("deterministic_header should be bool.")
        self._deterministic_header = deterministic_header

    @classmethod
    def new(
        cls,
        alg_auto_inclusion: bool = False,
        kid_auto_inclusion: bool = False,
        verify_kid: bool = False,
        ca_certs: str = "",
        deterministic_header: bool = False,
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
            deterministic_header(bool): The indicator whether the protected and unprotected
                headers will be deterministically encoded defined in section 4.2.1 of RFC 8949.
        """
        return cls(alg_auto_inclusion, kid_auto_inclusion, verify_kid, ca_certs, deterministic_header)

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

    def encode(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface] = None,
        protected: Optional[dict] = None,
        unprotected: Optional[dict] = None,
        recipients: List[RecipientInterface] = [],
        signers: List[Signer] = [],
        external_aad: bytes = b"",
        out: str = "",
        enable_non_aead: bool = False,
    ) -> bytes:
        """
        Encodes COSE message with MAC, signing and encryption.

        Args:
            payload (bytes): A content to be MACed, signed or encrypted.
            key (Optional[COSEKeyInterface]): A content encryption key as COSEKey.
            protected (Optional[dict]): Parameters that are to be cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            recipients (List[RecipientInterface]): A list of recipient information structures.
            signers (List[Signer]): A list of signer information objects for
                multiple signer cases.
            external_aad(bytes): External additional authenticated data supplied
                by application.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If
                ``"cbor2/CBORTag"`` is specified. This function will return encoded
                data as `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s
                ``CBORTag`` object. If any other value is specified, it will return
                encoded data as bytes.
            enable_non_aead (bool): Enable non-AEAD content ecnryption algorithms
                (False = disabled by default). Before enable non-AEAD ciphers,
                read and understand Security considerations of RFC 9459 carefully.
                Since non-AEAD ciphers DO NOT provide neither authentication nor integrity
                of decrypted message, make sure to deliver the encoded COSE message
                in conjunction with an authentication and integrity mechanisms,
                such as a digital signature.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a
                cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """
        p, u = self._encode_headers(key, protected, unprotected, enable_non_aead)
        typ = self._validate_cose_message(key, p, u, recipients, signers)
        if typ == 0:
            return self._encode_and_encrypt(payload, key, p, u, recipients, external_aad, out)
        elif typ == 1:
            return self._encode_and_mac(payload, key, p, u, recipients, external_aad, out)
        # elif typ == 2:
        return self._encode_and_sign(payload, key, p, u, signers, external_aad, out)

    def encode_and_encrypt(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface] = None,
        protected: Optional[dict] = None,
        unprotected: Optional[dict] = None,
        recipients: List[RecipientInterface] = [],
        external_aad: bytes = b"",
        out: str = "",
        enable_non_aead: bool = False,
    ) -> bytes:
        """
        Encodes data with encryption.

        Args:
            payload (bytes): A content to be encrypted.
            key (Optional[COSEKeyInterface]): A content encryption key as COSEKey.
            protected (Optional[dict]): Parameters that are to be cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            recipients (List[RecipientInterface]): A list of recipient information structures.
            external_aad(bytes): External additional authenticated data supplied
                by application.
            out(str): An output format. Only ``"cbor2/CBORTag"`` can be used. If
                ``"cbor2/CBORTag"`` is specified. This function will return encoded
                data as `cbor2 <https://cbor2.readthedocs.io/en/stable/>`_'s
                ``CBORTag`` object. If any other value is specified, it will return
                encoded data as bytes.
            enable_non_aead (bool): Enable non-AEAD content ecnryption algorithms
                (False = disabled by default). Before enable non-AEAD ciphers,
                read and understand Security considerations of RFC 9459 carefully.
                Since non-AEAD ciphers DO NOT provide neither authentication nor integrity
                of decrypted message, make sure to deliver the encoded COSE message
                in conjunction with an authentication and integrity mechanisms,
                such as a digital signature.
        Returns:
            Union[bytes, CBORTag]: A byte string of the encoded COSE or a
                cbor2.CBORTag object.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encode data.
        """
        p, u = self._encode_headers(key, protected, unprotected, enable_non_aead)
        typ = self._validate_cose_message(key, p, u, recipients, [])
        if typ != 0:
            raise ValueError("The COSE message is not suitable for COSE Encrypt0/Encrypt.")
        return self._encode_and_encrypt(payload, key, p, u, recipients, external_aad, out)

    def encode_and_mac(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface] = None,
        protected: Optional[dict] = None,
        unprotected: Optional[dict] = None,
        recipients: List[RecipientInterface] = [],
        external_aad: bytes = b"",
        out: str = "",
    ) -> Union[bytes, CBORTag]:
        """
        Encodes data with MAC.

        Args:
            payload (bytes): A content to be MACed.
            key (COSEKeyInterface): A COSE key as a MAC Authentication key.
            protected (Optional[dict]): Parameters that are to be cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
            recipients (List[RecipientInterface]): A list of recipient information structures.
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
        p, u = self._encode_headers(key, protected, unprotected, False)
        typ = self._validate_cose_message(key, p, u, recipients, [])
        if typ != 1:
            raise ValueError("The COSE message is not suitable for COSE MAC0/MAC.")
        return self._encode_and_mac(payload, key, p, u, recipients, external_aad, out)

    def encode_and_sign(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface] = None,
        protected: Optional[dict] = None,
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
            protected (Optional[dict]): Parameters that are to be cryptographically protected.
            unprotected (Optional[dict]): Parameters that are not cryptographically protected.
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
        p, u = self._encode_headers(key, protected, unprotected, False)
        typ = self._validate_cose_message(key, p, u, [], signers)
        if typ != 2:
            raise ValueError("The COSE message is not suitable for COSE Sign0/Sign.")
        return self._encode_and_sign(payload, key, p, u, signers, external_aad, out)

    def decode(
        self,
        data: Union[bytes, CBORTag],
        keys: Union[COSEKeyInterface, List[COSEKeyInterface]],
        context: Optional[Union[Dict[str, Any], List[Any]]] = None,
        external_aad: bytes = b"",
        detached_payload: Optional[bytes] = None,
        enable_non_aead: bool = False,
    ) -> bytes:
        """
        Verifies and decodes COSE data, and returns only payload.

        Args:
            data (Union[bytes, CBORTag]): A byte string or cbor2.CBORTag of an
                encoded data.
            keys (Union[COSEKeyInterface, List[COSEKeyInterface]]): COSE key(s)
                to verify and decrypt the encoded data.
            context (Optional[Union[Dict[str, Any], List[Any]]]): A context information
                structure for key deriviation functions.
            external_aad(bytes): External additional authenticated data supplied by
                application.
            detached_payload (Optional[bytes]): The detached payload that should be verified with data.
            enable_non_aead (bool): Enable non-AEAD content ecnryption algorithms
                (False = disabled by default). Before enable non-AEAD ciphers,
                read and understand Security considerations of RFC 9459 carefully.
                Since non-AEAD ciphers DO NOT provide neither authentication nor integrity
                of decrypted message, make sure to validate them outside of this library.
        Returns:
            bytes: A byte string of decoded payload.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode data.
            VerifyError: Failed to verify data.
        """
        _, _, res = self.decode_with_headers(data, keys, context, external_aad, detached_payload, enable_non_aead)
        return res

    def decode_with_headers(
        self,
        data: Union[bytes, CBORTag],
        keys: Union[COSEKeyInterface, List[COSEKeyInterface]],
        context: Optional[Union[Dict[str, Any], List[Any]]] = None,
        external_aad: bytes = b"",
        detached_payload: Optional[bytes] = None,
        enable_non_aead: bool = False,
    ) -> Tuple[Dict[int, Any], Dict[int, Any], bytes]:
        """
        Verifies and decodes COSE data, and returns protected headers, unprotected headers and payload.

        Args:
            data (Union[bytes, CBORTag]): A byte string or cbor2.CBORTag of an
                encoded data.
            keys (Union[COSEKeyInterface, List[COSEKeyInterface]]): COSE key(s)
                to verify and decrypt the encoded data.
            context (Optional[Union[Dict[str, Any], List[Any]]]): A context information
                structure for key deriviation functions.
            external_aad(bytes): External additional authenticated data supplied by
                application.
            detached_payload (Optional[bytes]): The detached payload that should be verified with data.
            enable_non_aead (bool): Enable non-AEAD content ecnryption algorithms
                (False = disabled by default). Before enable non-AEAD ciphers,
                read and understand Security considerations of RFC 9459 carefully.
                Since non-AEAD ciphers DO NOT provide neither authentication nor integrity
                of decrypted message, make sure to validate them outside of this library.
        Returns:
            Tuple[Dict[int, Any], Dict[int, Any], bytes]: A dictionary data of decoded protected headers, and a dictionary data of unprotected headers, and a byte string of decoded payload.
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

        payload = data.value[2]
        if detached_payload is not None:
            if data.value[2] is not None:
                raise ValueError("The payload already exists.")
            payload = detached_payload
        if payload is None:
            raise ValueError("detached_payload should be set.")

        # protected: Union[Dict[int, Any], bytes] = self._loads(data.value[0]) if data.value[0] else b""
        # unprotected = data.value[1]
        # if not isinstance(unprotected, dict):
        #     raise ValueError("unprotected header should be dict.")
        p, u = self._decode_headers(data.value[0], data.value[1])
        alg = p[1] if 1 in p else u.get(1, 0)
        if enable_non_aead is False and alg in COSE_ALGORITHMS_CEK_NON_AEAD.values():
            raise ValueError(f"Deprecated non-AEAD algorithm: {alg}.")

        # Local variable `protected` is byte encoded protected header
        # Sender is allowed to encode empty protected header into a bstr-wrapped zero-length map << {} >> (0x40A0)
        # but Recipient MUST treat it as a zero-length byte string h'' (0x40) while decoding
        protected = data.value[0] if len(p) > 0 else b""

        err: Exception = ValueError("key is not found.")

        # Encrypt0
        if data.tag == 16:
            kid = self._get_kid(p, u)
            aad = self._dumps(["Encrypt0", protected, external_aad])
            nonce = u.get(5, None)
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        if not isinstance(p, bytes) and alg in COSE_ALGORITHMS_HPKE.values():  # HPKE
                            hpke = HPKE(p, u, payload)
                            res = hpke.decode(k, aad)
                            if not isinstance(res, bytes):
                                raise TypeError("Internal type error.")
                            return p, u, res
                        return p, u, k.decrypt(payload, nonce, aad)
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    return p, u, k.decrypt(payload, nonce, aad)
                except Exception as e:
                    err = e
            raise err

        # Encrypt
        if data.tag == 96:
            rs = Recipients.from_list(data.value[3], self._verify_kid, context)
            nonce = u.get(5, b"")
            enc_key = rs.derive_key(keys, alg, external_aad, "Enc_Recipient")
            aad = self._dumps(["Encrypt", data.value[0], external_aad])
            return p, u, enc_key.decrypt(payload, nonce, aad)

        # MAC0
        if data.tag == 17:
            kid = self._get_kid(p, u)
            msg = self._dumps(["MAC0", protected, external_aad, payload])
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        k.verify(msg, data.value[3])
                        return p, u, payload
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    k.verify(msg, data.value[3])
                    return p, u, payload
                except Exception as e:
                    err = e
            raise err

        # MAC
        if data.tag == 97:
            to_be_maced = self._dumps(["MAC", protected, external_aad, payload])
            rs = Recipients.from_list(data.value[4], self._verify_kid, context)
            mac_auth_key = rs.derive_key(keys, alg, external_aad, "Mac_Recipient")
            mac_auth_key.verify(to_be_maced, data.value[3])
            return p, u, payload

        # Signature1
        if data.tag == 18:
            kid = self._get_kid(p, u)
            to_be_signed = self._dumps(["Signature1", protected, external_aad, payload])
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        if self._ca_certs:
                            k.validate_certificate(self._ca_certs)
                        k.verify(to_be_signed, data.value[3])
                        return p, u, payload
                    except Exception as e:
                        err = e
                raise err
            for _, k in enumerate(keys):
                try:
                    if self._ca_certs:
                        k.validate_certificate(self._ca_certs)
                    k.verify(to_be_signed, data.value[3])
                    return p, u, payload
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

            sp = self._loads(sig[0]) if sig[0] else b""
            su = sig[1]
            if not isinstance(su, dict):
                raise ValueError("unprotected header in signature structure should be dict.")
            kid = self._get_kid(sp, su)
            if kid:
                for _, k in enumerate(keys):
                    if k.kid != kid:
                        continue
                    try:
                        to_be_signed = self._dumps(
                            [
                                "Signature",
                                protected,
                                sig[0],
                                external_aad,
                                payload,
                            ]
                        )
                        k.verify(to_be_signed, sig[2])
                        return p, u, payload
                    except Exception as e:
                        err = e
                continue
            for _, k in enumerate(keys):
                try:
                    to_be_signed = self._dumps(
                        [
                            "Signature",
                            protected,
                            sig[0],
                            external_aad,
                            payload,
                        ]
                    )
                    k.verify(to_be_signed, sig[2])
                    return p, u, payload
                except Exception as e:
                    err = e
        raise err

    def _encode_headers(
        self,
        key: Optional[COSEKeyInterface],
        protected: Optional[dict],
        unprotected: Optional[dict],
        enable_non_aead: bool,
    ) -> Tuple[Dict[int, Any], Dict[int, Any]]:
        p = to_cose_header(protected)
        u = to_cose_header(unprotected)
        if key is not None:
            if self._alg_auto_inclusion:
                if key.alg in COSE_ALGORITHMS_CEK_NON_AEAD.values():
                    u[1] = key.alg
                else:
                    p[1] = key.alg
            if self._kid_auto_inclusion and key.kid:
                u[4] = key.kid

        # sort the key for deterministic encoding
        if self._deterministic_header:
            p = sort_keys_for_deterministic_encoding(p)
            u = sort_keys_for_deterministic_encoding(u)

        # Check the protected header is empty if the algorithm is non AEAD (AES-CBC or AES-CTR)
        # because section 4 of RFC9459 says "The 'protected' header MUST be a zero-length byte string."
        alg = p[1] if 1 in p else u.get(1, 0)
        if alg in COSE_ALGORITHMS_CEK_NON_AEAD.values():
            if enable_non_aead is False:
                raise ValueError(f"Deprecated non-AEAD algorithm: {alg}.")
            if len(p) > 0:
                raise ValueError("protected header MUST be zero-length")
        return p, u

    def _decode_headers(self, protected: Any, unprotected: Any) -> Tuple[Dict[int, Any], Dict[int, Any]]:
        p: Union[Dict[int, Any], bytes]
        p = self._loads(protected) if protected else {}
        if isinstance(p, bytes):
            if len(p) > 0:
                raise ValueError("Invalid protected header.")
            p = {}
        u: Dict[int, Any] = unprotected
        if not isinstance(u, dict):
            raise ValueError("unprotected header should be dict.")
        return p, u

    def _validate_cose_message(
        self,
        key: Optional[COSEKeyInterface],
        p: Dict[int, Any],
        u: Dict[int, Any],
        recipients: List[RecipientInterface],
        signers: List[Signer],
    ) -> int:
        if len(recipients) > 0 and len(signers) > 0:
            raise ValueError("Both recipients and signers are specified.")

        h: Dict[int, Any] = {}
        iv_count: int = 0
        for k, v in p.items():
            if k == 2:  # crit
                if not isinstance(v, list):
                    raise ValueError("crit parameter must have list.")
                for crit in v:
                    if not isinstance(crit, int):
                        raise ValueError("Integer labels for crit are only supported.")
                    if crit >= 0 and crit <= 7:
                        raise ValueError("Integer labels for crit in the range of 0 to 7 should be omitted.")
                    if crit not in p.keys() and crit not in u.keys():
                        raise ValueError(f"Integer label({crit}) for crit not found in the headers.")
            if k == 5 or k == 6:  # IV or Partial IV
                if not isinstance(v, bytes):
                    raise ValueError("IV and Partial IV must be bstr.")
                iv_count += 1
            h[k] = v
        for k, v in u.items():
            if k == 2:  # crit
                raise ValueError("crit(2) must be placed only in protected header.")
            if k == 5 or k == 6:  # IV or Partial IV
                if not isinstance(v, bytes):
                    raise ValueError("IV and Partial IV must be bstr.")
                iv_count += 1
            h[k] = v
        if len(h) != len(p) + len(u):
            raise ValueError("The same keys are both in protected and unprotected headers.")
        if iv_count > 1:
            raise ValueError("IV and Partial IV must not both be present in the same security layer.")

        if 1 in p and 1 in u:
            raise ValueError("alg appear both in protected and unprotected.")
        alg = p[1] if 1 in p else u.get(1, 0)

        if len(signers) > 0:
            return 2  # Sign

        if len(recipients) == 0:
            if key is None:
                raise ValueError("key should be set.")
            if alg not in COSE_ALGORITHMS_HPKE.values() and key.alg != alg:
                raise ValueError(f"The alg({alg}) in the headers does not match the alg({key.alg}) in the populated key.")
            if alg in COSE_ALGORITHMS_CEK.values():
                return 0  # Encrypt0
            if alg in COSE_ALGORITHMS_HPKE.values():
                return 0  # Encrypt0
            if alg in COSE_ALGORITHMS_MAC.values():
                return 1  # MAC0
            if alg in COSE_ALGORITHMS_SIGNATURE.values():
                return 2  # Sign0
            raise ValueError(f"Invalid alg for single-layer COSE message: {alg}.")

        if recipients[0].alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT.values():
            if len(recipients) > 1:
                raise ValueError("There must be only one recipient in direct key agreement mode.")

        if recipients[0].alg in COSE_ALGORITHMS_CKDM.values():  # Direct encryption mode.
            for r in recipients:
                if r.alg not in COSE_ALGORITHMS_CKDM.values():
                    raise ValueError("All of the recipient alg must be the direct encryption mode.")
                if len(r.recipients) > 0:
                    raise ValueError("Recipients for direct encryption mode don't have recipients.")
                if len(r.ciphertext) > 0:
                    raise ValueError(
                        "The ciphertext in the recipients for direct encryption mode must be a zero-length byte string."
                    )

        if recipients[0].alg in COSE_ALGORITHMS_KEY_WRAP.values():
            for r in recipients:
                if len(r.protected) > 0:
                    raise ValueError("The protected header must be a zero-length string in key wrap mode with an AE algorithm.")

        if (
            recipients[0].alg == -6  # direct
            or recipients[0].alg in COSE_ALGORITHMS_HPKE.values()
            or recipients[0].alg in COSE_ALGORITHMS_KEY_WRAP.values()
        ):
            if key is None:
                raise ValueError("key should be set.")
            if key.alg != alg:
                raise ValueError(f"The alg({alg}) in the headers does not match the alg({key.alg}) in the populated key.")
            if alg in COSE_ALGORITHMS_CEK.values():
                return 0  # Encrypt
            if alg in COSE_ALGORITHMS_HPKE.values():
                return 0  # Encrypt
            if alg in COSE_ALGORITHMS_MAC.values():
                return 1  # MAC
            raise ValueError(f"Invalid alg for single-layer COSE message: {alg}.")

        if (
            recipients[0].alg in COSE_ALGORITHMS_CKDM.values()
            or recipients[0].alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.values()
        ):
            if recipients[0].context[0] in COSE_ALGORITHMS_CEK.values():
                return 0  # Encrypt
            if recipients[0].context[0] in COSE_ALGORITHMS_HPKE.values():
                return 0  # Encrypt
            if recipients[0].context[0] in COSE_ALGORITHMS_KEY_WRAP.values():
                return 0  # Encrypt
            if recipients[0].context[0] in COSE_ALGORITHMS_MAC.values():
                return 1  # MAC
            raise ValueError(f"Invalid alg in recipients' context information: {recipients[0]._context[0]}.")

        raise ValueError(f"Unsupported or unknown alg: {alg}.")

    def _encode_and_encrypt(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface],
        p: Dict[int, Any],
        u: Dict[int, Any],
        recipients: List[RecipientInterface],
        external_aad: bytes,
        out: str,
    ) -> bytes:
        b_protected = self._dumps(p) if p else b""
        ciphertext: bytes = b""

        # Encrypt0
        if len(recipients) == 0:
            enc_structure = ["Encrypt0", b_protected, external_aad]
            aad = self._dumps(enc_structure)
            if 1 in p and p[1] in COSE_ALGORITHMS_HPKE.values():  # HPKE
                hpke = HPKE(p, u, recipient_key=key)
                encoded, _ = hpke.encode(payload, aad)
                res = CBORTag(16, encoded)
                return res if out == "cbor2/CBORTag" else self._dumps(res)
            if key is None:
                raise ValueError("key should be set.")
            if 5 not in u:  # nonce
                try:
                    u[5] = key.generate_nonce()
                except NotImplementedError:
                    raise ValueError("Nonce generation is not supported for the key. Set a nonce explicitly.")
            ciphertext = key.encrypt(payload, u[5], aad)
            res = CBORTag(16, [b_protected, u, ciphertext])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Encrypt
        if recipients[0].alg not in COSE_ALGORITHMS_RECIPIENT.values():
            raise NotImplementedError("Algorithms other than direct are not supported for recipients.")

        recs = []
        b_key = key.to_bytes() if isinstance(key, COSEKeyInterface) else b""
        cek: Optional[COSEKeyInterface] = None
        for rec in recipients:
            aad = self._dumps(["Enc_Recipient", self._dumps(rec.protected) if len(rec.protected) > 0 else b"", external_aad])
            encoded, derived_key = rec.encode(b_key, aad)
            cek = derived_key if derived_key else key
            recs.append(encoded)

        if cek is None:
            raise ValueError("key should be set.")
        if 5 not in u:  # nonce
            try:
                u[5] = cek.generate_nonce()
            except NotImplementedError:
                raise ValueError("Nonce generation is not supported for the key. Set a nonce explicitly.")
        enc_structure = ["Encrypt", b_protected, external_aad]
        aad = self._dumps(enc_structure)
        ciphertext = cek.encrypt(payload, u[5], aad)
        cose_enc: List[Any] = [b_protected, u, ciphertext]
        cose_enc.append(recs)
        res = CBORTag(96, cose_enc)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def _encode_and_mac(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface],
        p: Dict[int, Any],
        u: Dict[int, Any],
        recipients: List[RecipientInterface],
        external_aad: bytes,
        out: str,
    ) -> Union[bytes, CBORTag]:
        b_protected = self._dumps(p) if p else b""

        # MAC0
        if len(recipients) == 0:
            if key is None:
                raise ValueError("key should be set.")
            mac_structure = ["MAC0", b_protected, external_aad, payload]
            tag = key.sign(self._dumps(mac_structure))
            res = CBORTag(17, [b_protected, u, payload, tag])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # MAC
        if recipients[0].alg not in COSE_ALGORITHMS_RECIPIENT.values():
            raise NotImplementedError("Algorithms other than direct are not supported for recipients.")

        mac_structure = ["MAC", b_protected, external_aad, payload]

        recs = []
        b_key = key.to_bytes() if isinstance(key, COSEKeyInterface) else b""
        for rec in recipients:
            aad = self._dumps(["Mac_Recipient", self._dumps(rec.protected), external_aad])
            encoded, derived_key = rec.encode(b_key, aad)
            key = derived_key if derived_key else key
            recs.append(encoded)

        if key is None:
            raise ValueError("key should be set.")
        tag = key.sign(self._dumps(mac_structure))
        cose_mac: List[Any] = [b_protected, u, payload, tag]
        cose_mac.append(recs)
        res = CBORTag(97, cose_mac)
        return res if out == "cbor2/CBORTag" else self._dumps(res)

    def _encode_and_sign(
        self,
        payload: bytes,
        key: Optional[COSEKeyInterface],
        p: Dict[int, Any],
        u: Dict[int, Any],
        signers: List[Signer],
        external_aad: bytes,
        out: str,
    ) -> Union[bytes, CBORTag]:
        b_protected = self._dumps(p) if p else b""

        # Signature1
        if not signers and key is not None:
            sig_structure = ["Signature1", b_protected, external_aad, payload]
            sig = key.sign(self._dumps(sig_structure))
            res = CBORTag(18, [b_protected, u, payload, sig])
            return res if out == "cbor2/CBORTag" else self._dumps(res)

        # Signature
        sigs = []
        for s in signers:
            sig_structure = ["Signature", b_protected, s.protected, external_aad, payload]
            s.sign(self._dumps(sig_structure))
            sigs.append([s.protected, s.unprotected, s.signature])
        res = CBORTag(98, [b_protected, u, payload, sigs])
        return res if out == "cbor2/CBORTag" else self._dumps(res)

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
