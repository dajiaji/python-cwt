from typing import Any, Dict, List, Optional, Union

from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from .direct import Direct


class ECDH_DirectHKDF(Direct):
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

        if self._alg in [-25, -26]:  # ECDH-ES
            if -1 in self.unprotected:
                self.unprotected[-1][3] = self._alg
                self._sender_public_key = COSEKey.new(self.unprotected[-1])
        elif self._alg in [-27, -28]:  # ECDH-SS
            if -2 in self.unprotected:
                self.unprotected[-2][3] = self._alg
                self._sender_public_key = COSEKey.new(self.unprotected[-2])
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with HKDF: {self._alg}.")

    def apply(
        self,
        key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        alg: Optional[int] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:

        if not self._sender_key:
            raise ValueError("sender_key should be set in advance.")
        if not recipient_key:
            raise ValueError("recipient_key should be set in advance.")
        if not context:
            raise ValueError("context should be set.")
        derived_key = self._sender_key.derive_key(context, public_key=recipient_key)
        if self._alg in [-25, -26]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._sender_key.key.public_key())
        else:
            # ECDH-SS (alg=-27 or -28)
            self._unprotected[-2] = self._to_cose_key(self._sender_key.key.public_key())
        kid = self._kid if self._kid else recipient_key.kid
        if kid:
            self._unprotected[4] = kid
        return derived_key

    def extract(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:
        if not context:
            raise ValueError("context should be set.")
        return key.derive_key(context, public_key=self._sender_public_key)
