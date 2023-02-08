from secrets import token_bytes
from typing import Any, Dict, List, Optional, Tuple, Union

from ..algs.ec2 import EC2Key
from ..algs.okp import OKPKey
from ..const import COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError
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
        recipient_key: Optional[COSEKeyInterface] = None,
        context: List[Any] = [],
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._sender_public_key: Any = None
        self._sender_key = sender_key
        self._recipient_key = recipient_key
        self._context = context

        self._salt = None
        if -20 in unprotected:
            self._salt = unprotected[-20]

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

        # Generate a salt automatically if both of a salt and a PartyU nonce are not specified.
        if self._alg in [-27, -28]:  # ECDH-SS
            if not self._salt and not self._context[1][1]:
                self._salt = token_bytes(32) if self._alg == -27 else token_bytes(64)
                self._unprotected[-20] = self._salt

        # PartyU nonce
        if self._context[1][1]:
            self._unprotected[-22] = self._context[1][1]
        # PartyV nonce
        if self._context[2][1]:
            self._unprotected[-25] = self._context[2][1]

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        if not self._recipient_key:
            raise ValueError("recipient_key should be set in advance.")

        # Derive key.
        if self._alg in [-25, -26]:
            # ECDH-ES
            if self._recipient_key.kty == 2:
                self._sender_key = EC2Key({1: 2, -1: self._recipient_key.crv, 3: self._alg})
            else:
                # should drop this support.
                self._sender_key = OKPKey({1: 1, -1: self._recipient_key.crv, 3: self._alg})
        else:
            # ECDH-SS (alg=-27 or -28)
            if not self._sender_key:
                raise ValueError("sender_key should be set in advance.")

        derived_bytes = self._sender_key.derive_bytes(
            COSE_KEY_LEN[self._context[0]] // 8,
            info=self._dumps(self._context),
            public_key=self._recipient_key,
        )
        derived_key = COSEKey.from_symmetric_key(derived_bytes, alg=self._context[0])
        if self._alg in [-25, -26]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._sender_key.key.public_key())
        else:
            # ECDH-SS (alg=-27 or -28)
            self._unprotected[-2] = self._to_cose_key(self._sender_key.key.public_key())
        return self.to_list(), derived_key

    def decode(
        self,
        key: COSEKeyInterface,
        aad: bytes = b"",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        if not self._sender_public_key:
            raise ValueError("sender_public_key should be set.")
        try:
            derived_bytes = key.derive_bytes(
                COSE_KEY_LEN[self._context[0]] // 8,
                info=self._dumps(self._context),
                public_key=self._sender_public_key,
            )
        except Exception as err:
            raise DecodeError("Failed to decode.") from err
        if not as_cose_key:
            return derived_bytes
        return COSEKey.from_symmetric_key(derived_bytes, alg=self._context[0], kid=self._kid)
