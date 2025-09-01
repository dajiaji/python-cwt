from typing import Any, Dict, List, Optional, Tuple, Union

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..enums import COSEAlgs
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


def to_hpke_ciphersuites(alg: int) -> Tuple[int, int, int]:
    # New names
    if alg in [COSEAlgs.HPKE_0, COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM]:
        return 16, 1, 1
    if alg == COSEAlgs.HPKE_BASE_P256_SHA256_CHACHA20POLY1305:
        return 16, 1, 3
    if alg in [COSEAlgs.HPKE_1, COSEAlgs.HPKE_BASE_P384_SHA384_AES256GCM]:
        return 17, 2, 2
    if alg == COSEAlgs.HPKE_BASE_P384_SHA384_CHACHA20POLY1305:
        return 17, 2, 3
    if alg in [COSEAlgs.HPKE_2, COSEAlgs.HPKE_BASE_P521_SHA512_AES256GCM]:
        return 18, 3, 2
    if alg == COSEAlgs.HPKE_BASE_P521_SHA512_CHACHA20POLY1305:
        return 18, 3, 3
    if alg in [COSEAlgs.HPKE_3, COSEAlgs.HPKE_BASE_X25519_SHA256_AES128GCM]:
        return 32, 1, 1
    if alg in [COSEAlgs.HPKE_4, COSEAlgs.HPKE_BASE_X25519_SHA256_CHACHA20POLY1305]:
        return 32, 1, 3
    if alg in [COSEAlgs.HPKE_5, COSEAlgs.HPKE_BASE_X448_SHA512_AES256GCM]:
        return 33, 3, 2
    if alg in [COSEAlgs.HPKE_6, COSEAlgs.HPKE_BASE_X448_SHA512_CHACHA20POLY1305]:
        return 33, 3, 3
    raise ValueError("alg should be one of the HPKE algorithms.")


class HPKE(RecipientInterface):
    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        recipient_key: Optional[COSEKeyInterface] = None,
        psk: Optional[bytes] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._recipient_key = recipient_key
        self._psk = psk
        kem, kdf, aead = to_hpke_ciphersuites(self._alg)
        self._suite = CipherSuite.new(KEMId(kem), KDFId(kdf), AEADId(aead))
        return

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
            if psk_id is not None and self._psk is not None:
                enc, ctx = self._suite.create_sender_context(self._kem_key, psk=self._psk, psk_id=psk_id)
            else:
                enc, ctx = self._suite.create_sender_context(self._kem_key)
            if not isinstance(enc, (bytes, bytearray)):
                raise EncodeError("ek (-4) must be bstr.")
            self._unprotected[-4] = enc
            self._ciphertext = ctx.seal(plaintext, aad=aad)
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
            if psk_id is not None and self._psk is not None:
                ctx = self._suite.create_recipient_context(ek, self._to_kem_key(key), psk=self._psk, psk_id=psk_id)
            else:
                ctx = self._suite.create_recipient_context(ek, self._to_kem_key(key))
            raw = ctx.open(self._ciphertext, aad=aad)
            if not as_cose_key:
                return raw
            return COSEKey.from_symmetric_key(raw, alg=alg, kid=self._kid)
        except Exception as err:
            if isinstance(err, DecodeError):
                raise err
            raise DecodeError("Failed to open.") from err

    def _to_kem_key(self, src: COSEKeyInterface) -> KEMKeyInterface:
        return KEMKey.from_pyca_cryptography_key(src.key)
