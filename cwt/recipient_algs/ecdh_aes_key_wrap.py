from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


class ECDH_AESKeyWrap(RecipientInterface):
    _ACCEPTABLE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["deriveKey"],
        COSE_KEY_OPERATION_VALUES["deriveBits"],
    ]

    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        cose_key: Optional[COSEKeyInterface] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._peer_public_key: Any = None
        self._cose_key = cose_key
        self._wrapping_key: Any = None

        self._apu = [
            self.unprotected[-21] if -21 in self.unprotected else None,
            self.unprotected[-22] if -22 in self.unprotected else None,
            self.unprotected[-23] if -23 in self.unprotected else None,
        ]
        self._apv = [
            self.unprotected[-24] if -24 in self.unprotected else None,
            self.unprotected[-25] if -25 in self.unprotected else None,
            self.unprotected[-26] if -26 in self.unprotected else None,
        ]

        if self._alg in [-29, -30, -31]:  # ECDH-ES
            if -1 in self.unprotected:
                self._unprotected[-1][3] = self._alg
                self._peer_public_key = COSEKey.new(self.unprotected[-1])
                self._key = self._peer_public_key.key
        elif self._alg in [-32, -33, -34]:  # ECDH-SS
            if -2 in self.unprotected:
                self._unprotected[-2][3] = self._alg
                self._peer_public_key = COSEKey.new(self.unprotected[-2])
                self._key = self._peer_public_key.key
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with key wrap: {self._alg}.")

    def derive_key(
        self,
        context: Union[List[Any], Dict[str, Any]],
        material: bytes = b"",
        public_key: Optional[COSEKeyInterface] = None,
    ) -> COSEKeyInterface:

        if not self._cose_key:
            raise ValueError(
                "Internal COSE key should be set for key derivation in advance."
            )
        public_key = public_key if public_key else self._peer_public_key
        if not public_key:
            raise ValueError("public_key should be set.")
        self._wrapping_key = self._cose_key.derive_key(context, public_key=public_key)
        if self._alg in [-29, -30, -31]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._cose_key.key.public_key())
        else:
            # ECDH-SS (alg=-32, -33, -34)
            self._unprotected[-2] = self._to_cose_key(self._cose_key.key.public_key())
        kid = self._kid if self._kid else public_key.kid
        if kid:
            self._unprotected[4] = kid
        return self._wrapping_key

    def wrap_key(self, key_to_wrap: bytes):
        if not self._wrapping_key:
            raise EncodeError("Should call derive_key() before calling wrap_key().")
        try:
            self._ciphertext = aes_key_wrap(self._wrapping_key.key, key_to_wrap)
        except Exception as err:
            raise EncodeError("Failed to wrap key.") from err

    def unwrap_key(self, alg: int) -> COSEKeyInterface:
        try:
            key = aes_key_unwrap(self._key, self._ciphertext)
            return COSEKey.from_symmetric_key(key, alg=alg, kid=self._kid)
        except Exception as err:
            raise DecodeError("Failed to unwrap key.") from err
