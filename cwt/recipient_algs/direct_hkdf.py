from typing import Any, Dict, List, Optional, Union

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
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._hash_alg: Any = None
        self._salt = None

        if -20 not in unprotected and -22 not in unprotected:
            raise ValueError("salt(-20) or PartyU nonce(-22) should be set.")
        if -20 in unprotected:
            self._salt = unprotected[-20]
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

        if self._alg == -10:  # direct+HKDF-SHA-256
            self._hash_alg = hashes.SHA256()
        elif self._alg == -11:  # direct+HKDF-SHA-512
            self._hash_alg = hashes.SHA512()
        else:
            raise ValueError(f"Unknown alg(3) for direct key with KDF: {self._alg}.")

    def derive_key(
        self,
        context: Union[List[Any], Dict[str, Any]],
        material: bytes = b"",
        public_key: Optional[COSEKeyInterface] = None,
    ) -> COSEKeyInterface:

        if isinstance(context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            context = to_cis(context, alg)
        else:
            self._validate_context(context)

        # Derive key.
        hkdf = HKDF(
            algorithm=self._hash_alg,
            length=COSE_KEY_LEN[context[0]] // 8,
            salt=self._salt,
            info=self._dumps(context),
        )
        try:
            key = hkdf.derive(material)
            return COSEKey.from_symmetric_key(key, alg=context[0], kid=self._kid)
        except Exception as err:
            raise EncodeError("Failed to derive key.") from err

    def verify_key(
        self,
        material: bytes,
        expected_key: bytes,
        context: Union[List[Any], Dict[str, Any]],
    ):

        if isinstance(context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            context = to_cis(context, alg)
        else:
            self._validate_context(context)

        # Verify key.
        try:
            hkdf = HKDF(
                algorithm=self._hash_alg,
                length=COSE_KEY_LEN[context[0]] // 8,
                salt=self._salt,
                info=self._dumps(context),
            )
            hkdf.verify(material, expected_key)
        except Exception as err:
            raise VerifyError("Failed to verify key.") from err
        return
