from secrets import token_bytes
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..const import COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError, VerifyError
from .direct import Direct


class DirectHKDF(Direct):
    _ACCEPTABLE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["deriveKey"],
        COSE_KEY_OPERATION_VALUES["deriveBits"],
    ]

    def __init__(
        self,
        protected: Dict[int, Any] = {},
        unprotected: Dict[int, Any] = {},
        context: List[Any] = [],
    ):
        super().__init__(protected, unprotected, b"", [])

        self._context = context

        self._salt = None
        if -20 in unprotected:
            self._salt = unprotected[-20]

        self._hash_alg: Any = None
        if self._alg == -10:  # direct+HKDF-SHA-256
            self._hash_alg = hashes.SHA256()
        elif self._alg == -11:  # direct+HKDF-SHA-512
            self._hash_alg = hashes.SHA512()
        else:
            raise ValueError(f"Unknown alg(3) for direct key with KDF: {self._alg}.")

        # Generate a salt automatically if both of a salt and a PartyU nonce are not specified.
        if not self._salt and not self._context[1][1]:
            self._salt = token_bytes(32) if self._alg == -10 else token_bytes(64)
            self._unprotected[-20] = self._salt

        # PartyU nonce
        if self._context[1][1]:
            self._unprotected[-22] = self._context[1][1]
        # PartyV nonce
        if self._context[2][1]:
            self._unprotected[-25] = self._context[2][1]

    def verify_key(
        self,
        material: bytes,
        expected_key: bytes,
    ):
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

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        try:
            hkdf = HKDF(
                algorithm=self._hash_alg,
                length=COSE_KEY_LEN[self._context[0]] // 8,
                salt=self._salt,
                info=self._dumps(self._context),
            )
            derived = hkdf.derive(plaintext)
            return self.to_list(), COSEKey.from_symmetric_key(derived, self._context[0], kid=self._kid)
        except Exception as err:
            raise EncodeError("Failed to derive key.") from err

    def decode(
        self, key: COSEKeyInterface, aad: bytes = b"", alg: int = 0, as_cose_key: bool = False
    ) -> Union[bytes, COSEKeyInterface]:
        try:
            hkdf = HKDF(
                algorithm=self._hash_alg,
                length=COSE_KEY_LEN[self._context[0]] // 8,
                salt=self._salt,
                info=self._dumps(self._context),
            )
            derived = hkdf.derive(key.key)
            if not as_cose_key:
                return derived
            return COSEKey.from_symmetric_key(derived, alg=self._context[0], kid=self._kid)
        except Exception as err:
            raise DecodeError("Failed to decode.") from err
