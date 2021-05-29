from typing import Any, Dict, List, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..const import COSE_ALGORITHMS_SYMMETRIC, COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
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
        self._party_u = [
            self.unprotected[-21] if -21 in self.unprotected else None,
            self.unprotected[-22] if -22 in self.unprotected else None,
            self.unprotected[-23] if -23 in self.unprotected else None,
        ]
        self._party_v = [
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
        self, material: bytes, context: Union[List[Any], Dict[str, Any]]
    ) -> COSEKeyInterface:

        if isinstance(context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            context = to_cis(context, recipient_alg=alg)
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
            context = to_cis(context, recipient_alg=alg)
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

    def _validate_context(self, context: List[Any]):
        if len(context) != 4 and len(context) != 5:
            raise ValueError("Invalid context information.")
        # AlgorithmID
        if not isinstance(context[0], int):
            raise ValueError("AlgorithmID should be int.")
        if context[0] not in COSE_ALGORITHMS_SYMMETRIC.values():
            raise ValueError(f"Unsupported or unknown algorithm: {context[0]}.")
        # PartyVInfo
        if not isinstance(context[1], list) or len(context[1]) != 3:
            raise ValueError("PartyUInfo should be list(size=3).")
        # PartyUInfo
        if not isinstance(context[2], list) or len(context[2]) != 3:
            raise ValueError("PartyVInfo should be list(size=3).")
        # SuppPubInfo
        if not isinstance(context[3], list) or (
            len(context[3]) != 2 and len(context[3]) != 3
        ):
            raise ValueError("SuppPubInfo should be list(size=2 or 3).")
