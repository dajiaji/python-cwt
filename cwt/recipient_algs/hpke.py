from typing import Any, Dict, List, Optional, Tuple, Union

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..enums import COSEAlgs
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


def to_hpke_ciphersuites(alg: int) -> Tuple[int, int, int]:
    if alg == COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM:
        return 16, 1, 1
    if alg == COSEAlgs.HPKE_BASE_P256_SHA256_CHACHA20POLY1305:
        return 16, 1, 3
    if alg == COSEAlgs.HPKE_BASE_P384_SHA384_AES256GCM:
        return 17, 2, 2
    if alg == COSEAlgs.HPKE_BASE_P384_SHA384_CHACHA20POLY1305:
        return 17, 2, 3
    if alg == COSEAlgs.HPKE_BASE_P521_SHA512_AES256GCM:
        return 18, 3, 2
    if alg == COSEAlgs.HPKE_BASE_P521_SHA512_CHACHA20POLY1305:
        return 18, 3, 3
    if alg == COSEAlgs.HPKE_BASE_X25519_SHA256_AES128GCM:
        return 32, 1, 1
    if alg == COSEAlgs.HPKE_BASE_X25519_SHA256_CHACHA20POLY1305:
        return 32, 1, 3
    if alg == COSEAlgs.HPKE_BASE_X448_SHA512_AES256GCM:
        return 33, 3, 2
    if alg == COSEAlgs.HPKE_BASE_X448_SHA512_CHACHA20POLY1305:
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
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._recipient_key = recipient_key
        kem, kdf, aead = to_hpke_ciphersuites(self._alg)
        self._suite = CipherSuite.new(KEMId(kem), KDFId(kdf), AEADId(aead))
        return

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        if self._recipient_key is None:
            raise ValueError("recipient_key should be set in advance.")
        self._kem_key = self._to_kem_key(self._recipient_key)
        try:
            enc, ctx = self._suite.create_sender_context(self._kem_key)
            self._unprotected[-4] = enc
            self._ciphertext = ctx.seal(plaintext, aad=aad)
        except Exception as err:
            raise EncodeError("Failed to seal.") from err
        return self.to_list(), None

    def decode(
        self,
        key: COSEKeyInterface,
        aad: bytes = b"",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        try:
            ctx = self._suite.create_recipient_context(self._unprotected[-4], self._to_kem_key(key))
            raw = ctx.open(self._ciphertext, aad=aad)
            if not as_cose_key:
                return raw
            return COSEKey.from_symmetric_key(raw, alg=alg, kid=self._kid)
        except Exception as err:
            raise DecodeError("Failed to open.") from err

    def _to_kem_key(self, src: COSEKeyInterface) -> KEMKeyInterface:
        return KEMKey.from_pyca_cryptography_key(src.key)
