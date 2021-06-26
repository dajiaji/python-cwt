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
        sender_key: Optional[COSEKeyInterface] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._sender_public_key: Any = None
        self._sender_key = sender_key

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
                self._sender_public_key = COSEKey.new(self.unprotected[-1])
        elif self._alg in [-32, -33, -34]:  # ECDH-SS
            if -2 in self.unprotected:
                self._unprotected[-2][3] = self._alg
                self._sender_public_key = COSEKey.new(self.unprotected[-2])
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with key wrap: {self._alg}.")

    def apply(
        self,
        key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        salt: Optional[bytes] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:

        if not key:
            raise ValueError("key should be set.")
        if not recipient_key:
            raise ValueError("recipient_key should be set in advance.")
        if not self._sender_key:
            raise ValueError("sender_key should be set in advance.")
        if not context:
            raise ValueError("context should be set.")
        wrapping_key = self._sender_key.derive_key(context, public_key=recipient_key)
        if self._alg in [-29, -30, -31]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._sender_key.key.public_key())
        else:
            # ECDH-SS (alg=-32, -33, -34)
            self._unprotected[-2] = self._to_cose_key(self._sender_key.key.public_key())
        kid = self._kid if self._kid else recipient_key.kid
        if kid:
            self._unprotected[4] = kid
        try:
            self._ciphertext = aes_key_wrap(wrapping_key.key, key.key)
        except Exception as err:
            raise EncodeError("Failed to wrap key.") from err
        return key

    def extract(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:
        if not alg:
            raise ValueError("alg should be set.")
        if not context:
            raise ValueError("context should be set.")
        try:
            derived = key.derive_key(context, public_key=self._sender_public_key)
            unwrapped = aes_key_unwrap(derived.key, self._ciphertext)
            return COSEKey.from_symmetric_key(unwrapped, alg=alg, kid=self._kid)
        except Exception as err:
            raise DecodeError("Failed to decode key.") from err
