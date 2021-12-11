import copy
from secrets import token_bytes
from typing import Any, Dict, List, Optional, Union

from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..utils import to_cis
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

        self._salt = None
        if -20 in unprotected:
            self._salt = unprotected[-20]

        self._default_ctx: List[Any] = [
            None,
            [
                self.unprotected[-21] if -21 in self.unprotected else None,
                self.unprotected[-22] if -22 in self.unprotected else None,
                self.unprotected[-23] if -23 in self.unprotected else None,
            ],
            [
                self.unprotected[-24] if -24 in self.unprotected else None,
                self.unprotected[-25] if -25 in self.unprotected else None,
                self.unprotected[-26] if -26 in self.unprotected else None,
            ],
            [None, None],
        ]
        self._applied_ctx: Union[list, None] = None

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
        salt: Optional[bytes] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:

        if not self._sender_key:
            raise ValueError("sender_key should be set in advance.")
        if not recipient_key:
            raise ValueError("recipient_key should be set in advance.")
        if not context:
            raise ValueError("context should be set.")
        ctx: list
        if isinstance(context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            ctx = to_cis(context, alg)
        else:
            self._validate_context(context)
            ctx = context
        self._applied_ctx = self._apply_context(ctx)

        # Generate a salt automatically if both of a salt and a PartyU nonce are not specified.
        if self._alg in [-27, -28]:  # ECDH-SS
            if not salt and not self._salt and not self._applied_ctx[1][1]:
                self._salt = token_bytes(32) if self._alg == -27 else token_bytes(64)
                self._unprotected[-20] = self._salt
            elif salt:
                self._salt = salt
                self._unprotected[-20] = self._salt

        # PartyU nonce
        if self._applied_ctx[1][1]:
            self._unprotected[-22] = self._applied_ctx[1][1]
        # PartyV nonce
        if self._applied_ctx[2][1]:
            self._unprotected[-25] = self._applied_ctx[2][1]

        # Derive key.
        derived_key = self._sender_key.derive_key(self._applied_ctx, public_key=recipient_key)
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

    def _apply_context(self, given: list) -> list:
        ctx = copy.deepcopy(self._default_ctx)
        for i, item in enumerate(given):
            if i == 0:
                ctx[0] = item
                continue
            for j, v in enumerate(item):
                if not v:
                    continue
                if i != 3 or j != 2:
                    ctx[i][j] = v
                else:
                    ctx[i].append(v)
        return ctx
