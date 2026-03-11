from typing import Any, Dict, List, Optional, Tuple, Union

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface

# KE algorithm IDs (HPKE-0-KE through HPKE-7-KE)
_HPKE_KE_ALGS = {46, 47, 48, 49, 50, 51, 52, 53}

# Map KE algorithm IDs to their base (Integrated) counterpart
_KE_TO_BASE = {
    46: 35,  # HPKE-0-KE -> HPKE-0
    47: 37,  # HPKE-1-KE -> HPKE-1
    48: 39,  # HPKE-2-KE -> HPKE-2
    49: 41,  # HPKE-3-KE -> HPKE-3
    50: 42,  # HPKE-4-KE -> HPKE-4
    51: 43,  # HPKE-5-KE -> HPKE-5
    52: 44,  # HPKE-6-KE -> HPKE-6
    53: 45,  # HPKE-7-KE -> HPKE-7
}

# KEM/KDF/AEAD ciphersuite table keyed by base algorithm ID
_HPKE_SUITES = {
    35: (16, 1, 1),  # HPKE-0: DHKEM(P-256) + HKDF-SHA256 + AES-128-GCM
    37: (17, 2, 2),  # HPKE-1: DHKEM(P-384) + HKDF-SHA384 + AES-256-GCM
    39: (18, 3, 2),  # HPKE-2: DHKEM(P-521) + HKDF-SHA512 + AES-256-GCM
    41: (32, 1, 1),  # HPKE-3: DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM
    42: (32, 1, 3),  # HPKE-4: DHKEM(X25519) + HKDF-SHA256 + ChaCha20Poly1305
    43: (33, 3, 2),  # HPKE-5: DHKEM(X448) + HKDF-SHA512 + AES-256-GCM
    44: (33, 3, 3),  # HPKE-6: DHKEM(X448) + HKDF-SHA512 + ChaCha20Poly1305
    45: (16, 1, 2),  # HPKE-7: DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM
}


def to_hpke_ciphersuites(alg: int) -> Tuple[int, int, int]:
    base_alg = _KE_TO_BASE.get(alg, alg)
    if base_alg in _HPKE_SUITES:
        return _HPKE_SUITES[base_alg]
    raise ValueError("alg should be one of the HPKE algorithms.")


def is_hpke_ke(alg: int) -> bool:
    return alg in _HPKE_KE_ALGS


class HPKE(RecipientInterface):
    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        recipient_key: Optional[COSEKeyInterface] = None,
        psk: Optional[bytes] = None,
        content_alg: int = 0,
        extra_info: bytes = b"",
        hpke_info: bytes = b"",
        hpke_aad: bytes = b"",
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._recipient_key = recipient_key
        self._psk = psk
        self._content_alg = content_alg
        self._extra_info = extra_info
        self._hpke_info = hpke_info
        self._hpke_aad = hpke_aad
        kem, kdf, aead = to_hpke_ciphersuites(self._alg)
        self._suite = CipherSuite.new(KEMId(kem), KDFId(kdf), AEADId(aead))
        return

    @property
    def content_alg(self) -> int:
        return self._content_alg

    @content_alg.setter
    def content_alg(self, value: int):
        self._content_alg = value

    def _build_recipient_info(self, content_alg: int) -> bytes:
        """Build the Recipient_structure for Key Encryption mode (draft-ietf-cose-hpke-23).

        Recipient_structure = [
            context: "HPKE Recipient",
            next_layer_alg: int,
            recipient_protected_header: bstr,
            recipient_extra_info: bstr,
        ]
        """
        recipient_structure = [
            "HPKE Recipient",
            content_alg,
            self.b_protected,
            self._extra_info,
        ]
        return self._dumps(recipient_structure)

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        if self._recipient_key is None:
            raise ValueError("recipient_key should be set in advance.")
        self._kem_key = self._to_kem_key(self._recipient_key)
        try:
            psk_id = self._unprotected.get(-5, None)
            if psk_id is not None and not isinstance(psk_id, (bytes, bytearray)):
                raise EncodeError("psk_id (-5) must be bstr.")
            if self._psk is not None and psk_id is None:
                raise EncodeError("psk_id (-5) is required when hpke_psk is provided.")
            if psk_id is not None and self._psk is None:
                raise EncodeError("hpke_psk is required when psk_id (-5) is provided.")

            # Build HPKE info parameter
            if is_hpke_ke(self._alg):
                info = self._build_recipient_info(self._content_alg)
            else:
                info = self._hpke_info

            if psk_id is not None and self._psk is not None:
                enc, ctx = self._suite.create_sender_context(self._kem_key, info=info, psk=self._psk, psk_id=psk_id)
            else:
                enc, ctx = self._suite.create_sender_context(self._kem_key, info=info)
            if not isinstance(enc, (bytes, bytearray)):
                raise EncodeError("ek (-4) must be bstr.")
            self._unprotected[-4] = enc
            # KE mode: use hpke_aad; Integrated mode: use passed-in aad (Enc_structure)
            seal_aad = self._hpke_aad if is_hpke_ke(self._alg) else aad
            self._ciphertext = ctx.seal(plaintext, aad=seal_aad)
        except Exception as err:
            if isinstance(err, EncodeError):
                raise err
            raise EncodeError("Failed to seal.") from err
        return self.to_list(), None

    def decode(
        self,
        key: COSEKeyInterface,
        aad: bytes = b"",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        ek = self._unprotected.get(-4, None)
        if ek is None and isinstance(self._protected, dict):
            ek = self._protected.get(-4, None)
        if ek is None:
            raise DecodeError("ek (-4) is required for HPKE.")
        if not isinstance(ek, (bytes, bytearray)):
            raise DecodeError("ek (-4) must be bstr.")
        try:
            psk_id = self._unprotected.get(-5, None)
            if psk_id is not None and not isinstance(psk_id, (bytes, bytearray)):
                raise DecodeError("psk_id (-5) must be bstr.")
            if self._psk is not None and psk_id is None:
                raise DecodeError("psk_id (-5) is required when hpke_psk is provided.")
            if psk_id is not None and self._psk is None:
                raise DecodeError("hpke_psk is required when psk_id (-5) is provided.")

            # Build HPKE info parameter
            if is_hpke_ke(self._alg):
                info = self._build_recipient_info(alg)
            else:
                info = self._hpke_info

            if psk_id is not None and self._psk is not None:
                ctx = self._suite.create_recipient_context(ek, self._to_kem_key(key), info=info, psk=self._psk, psk_id=psk_id)
            else:
                ctx = self._suite.create_recipient_context(ek, self._to_kem_key(key), info=info)
            # KE mode: use hpke_aad; Integrated mode: use passed-in aad (Enc_structure)
            open_aad = self._hpke_aad if is_hpke_ke(self._alg) else aad
            raw = ctx.open(self._ciphertext, aad=open_aad)
            if not as_cose_key:
                return raw
            return COSEKey.from_symmetric_key(raw, alg=alg, kid=self._kid)
        except Exception as err:
            if isinstance(err, DecodeError):
                raise err
            raise DecodeError("Failed to open.") from err

    def _to_kem_key(self, src: COSEKeyInterface) -> KEMKeyInterface:
        return KEMKey.from_pyca_cryptography_key(src.key)
