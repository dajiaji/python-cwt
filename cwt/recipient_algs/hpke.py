from typing import Any, Dict, List, Optional, Tuple, Union

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


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

        if self._alg != -1:
            raise ValueError("alg should be HPKE(-1).")
        if -4 not in unprotected:
            raise ValueError("HPKE sender information(-4) not found.")
        if 1 not in unprotected[-4]:
            raise ValueError("kem id(1) not found in HPKE sender information(-4).")
        if 2 not in unprotected[-4]:
            raise ValueError("kdf id(2) not found in HPKE sender information(-4).")
        if 3 not in unprotected[-4]:
            raise ValueError("aead id(3) not found in HPKE sender information(-4).")
        self._suite = CipherSuite.new(KEMId(unprotected[-4][1]), KDFId(unprotected[-4][2]), AEADId(unprotected[-4][3]))
        return

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        if self._recipient_key is None:
            raise ValueError("recipient_key should be set in advance.")
        self._kem_key = self._to_kem_key(self._recipient_key)
        try:
            enc, ctx = self._suite.create_sender_context(self._kem_key)
            self._unprotected[-4][4] = enc
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
            ctx = self._suite.create_recipient_context(self._unprotected[-4][4], self._to_kem_key(key))
            raw = ctx.open(self._ciphertext, aad=aad)
            if not as_cose_key:
                return raw
            return COSEKey.from_symmetric_key(raw, alg=alg, kid=self._kid)
        except Exception as err:
            raise DecodeError("Failed to open.") from err

    def _to_kem_key(self, src: COSEKeyInterface) -> KEMKeyInterface:
        return KEMKey.from_pyca_cryptography_key(src.key)
