import copy
from secrets import token_bytes
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..const import COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import EncodeError, VerifyError
from ..utils import to_cis
from .direct import Direct


class DirectHKDF(Direct):
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
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)

        if not context:
            raise ValueError("context should be set.")
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

        self._hash_alg: Any = None
        if self._alg == -10:  # direct+HKDF-SHA-256
            self._hash_alg = hashes.SHA256()
        elif self._alg == -11:  # direct+HKDF-SHA-512
            self._hash_alg = hashes.SHA512()
        else:
            raise ValueError(f"Unknown alg(3) for direct key with KDF: {self._alg}.")

        ctx: list
        if isinstance(self._context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            ctx = to_cis(self._context, alg)
        else:
            self._validate_context(self._context)
            ctx = self._context
        self._applied_ctx = self._apply_context(ctx)

        # Generate a salt automatically if both of a salt and a PartyU nonce are not specified.
        if not self._salt and not self._applied_ctx[1][1]:
            self._salt = token_bytes(32) if self._alg == -10 else token_bytes(64)
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

    def verify_key(
        self,
        material: bytes,
        expected_key: bytes,
    ):

        if isinstance(self._context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            self._context = to_cis(self._context, alg)
        else:
            self._validate_context(self._context)

        # Verify key.
        try:
            hkdf = HKDF(
                algorithm=self._hash_alg,
                length=COSE_KEY_LEN[self._context[0]] // 8,
                salt=self._salt,
                info=self._dumps(self._context),
            )
            hkdf.verify(material, expected_key)
        except Exception as err:
            raise VerifyError("Failed to verify key.") from err
        return

    def encode(
        self,
        plaintext: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> Tuple[List[Any], Optional[COSEKeyInterface]]:

        # Derive key.
        try:
            hkdf = HKDF(
                algorithm=self._hash_alg,
                length=COSE_KEY_LEN[self._applied_ctx[0]] // 8,
                salt=self._salt,
                info=self._dumps(self._applied_ctx),
            )
            derived = hkdf.derive(plaintext)
            return self.to_list(), COSEKey.from_symmetric_key(derived, self._applied_ctx[0], self._kid)
        except Exception as err:
            raise EncodeError("Failed to derive key.") from err

    def apply(
        self,
        key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        salt: Optional[bytes] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> COSEKeyInterface:

        if not key:
            raise ValueError("key should be set.")
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
        if not salt and not self._salt and not self._applied_ctx[1][1]:
            self._salt = token_bytes(32) if self._alg == -10 else token_bytes(64)
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
        hkdf = HKDF(
            algorithm=self._hash_alg,
            length=COSE_KEY_LEN[self._applied_ctx[0]] // 8,
            salt=self._salt,
            info=self._dumps(self._applied_ctx),
        )
        try:
            derived = hkdf.derive(key.key)
            if key.kid:
                self._unprotected[4] = key.kid
            return COSEKey.from_symmetric_key(derived, self._applied_ctx[0], self._kid)
        except Exception as err:
            raise EncodeError("Failed to derive key.") from err

    def extract(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
    ) -> COSEKeyInterface:

        if not self._context:
            raise ValueError("context should be set.")
        if isinstance(self._context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            self._context = to_cis(self._context, alg)
        else:
            self._validate_context(self._context)

        # Derive key.
        hkdf = HKDF(
            algorithm=self._hash_alg,
            length=COSE_KEY_LEN[self._context[0]] // 8,
            salt=self._salt,
            info=self._dumps(self._context),
        )
        derived = hkdf.derive(key.key)
        return COSEKey.from_symmetric_key(derived, alg=self._context[0], kid=self._kid)

    def decrypt(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
        payload: bytes = b"",
        nonce: bytes = b"",
        aad: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> bytes:
        return self.extract(key, alg).decrypt(payload, nonce, aad)

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
