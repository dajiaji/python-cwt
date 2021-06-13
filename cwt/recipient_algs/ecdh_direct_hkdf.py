from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from ..algs.ec2 import EC2Key
from ..algs.okp import OKPKey
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
        cose_key: Optional[COSEKeyInterface] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._peer_public_key: Any = None
        self._cose_key = cose_key

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
                self._peer_public_key = COSEKey.new(self.unprotected[-1])
                self._key = self._peer_public_key.key
        elif self._alg in [-27, -28]:  # ECDH-SS
            if -2 in self.unprotected:
                self._peer_public_key = COSEKey.new(self.unprotected[-2])
                self._key = self._peer_public_key.key
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with HKDF: {self._alg}.")

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
        kid = self._kid if self._kid else public_key.kid
        if kid:
            self._unprotected[4] = kid
        derived_key = self._cose_key.derive_key(context, public_key=public_key)
        if self._alg in [-25, -26]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._cose_key.key.public_key())
            self._unprotected[-1][3] = self._alg
        else:
            # ECDH-SS (alg=-27 or -28)
            self._unprotected[-2] = self._to_cose_key(self._cose_key.key.public_key())
            self._unprotected[-2][3] = self._alg
        return derived_key

    def _to_cose_key(
        self, k: Union[EllipticCurvePublicKey, X25519PublicKey, X448PublicKey]
    ) -> Dict[int, Any]:
        if isinstance(k, EllipticCurvePublicKey):
            return EC2Key.to_cose_key(k)
        return OKPKey.to_cose_key(k)
