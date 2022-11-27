import copy
from secrets import token_bytes
from typing import Any, Dict, List, Optional, Tuple, Union

from ..algs.ec2 import EC2Key
from ..algs.okp import OKPKey
from ..const import COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError
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
        recipient_key: Optional[COSEKeyInterface] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._sender_public_key: Any = None
        self._sender_key = sender_key
        self._recipient_key = recipient_key
        if not context:
            raise ValueError("context should be set in advance.")
        self._context = context

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
        self._applied_ctx: list

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

        ctx: list
        if isinstance(self._context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            ctx = to_cis(self._context, alg)
        else:
            self._validate_context(self._context)
            ctx = self._context
        self._applied_ctx = self._apply_context(ctx)

        # Generate a salt automatically if both of a salt and a PartyU nonce are not specified.
        if self._alg in [-27, -28]:  # ECDH-SS
            if not self._salt and not self._applied_ctx[1][1]:
                self._salt = token_bytes(32) if self._alg == -27 else token_bytes(64)
                self._unprotected[-20] = self._salt
            # elif salt:
            #     self._salt = salt
            #     self._unprotected[-20] = self._salt

        # PartyU nonce
        if self._applied_ctx[1][1]:
            self._unprotected[-22] = self._applied_ctx[1][1]
        # PartyV nonce
        if self._applied_ctx[2][1]:
            self._unprotected[-25] = self._applied_ctx[2][1]

    def encode(
        self,
        plaintext: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> Tuple[List[Any], Optional[COSEKeyInterface]]:

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

        derived_key = self._sender_key.derive_key(self._applied_ctx, public_key=self._recipient_key)
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
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        if not self._sender_public_key:
            raise ValueError("sender_public_key should be set.")
        try:
            if not as_cose_key:
                return key.derive_bytes(
                    COSE_KEY_LEN[self._applied_ctx[0]] // 8,
                    info=self._dumps(self._applied_ctx),
                    public_key=self._sender_public_key,
                )
            return key.derive_key(self._applied_ctx, public_key=self._sender_public_key)
        except Exception as err:
            raise DecodeError("Failed to decode.") from err

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
