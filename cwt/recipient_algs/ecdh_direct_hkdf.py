from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..algs.ec2 import EC2Key
from ..const import COSE_KEY_LEN, COSE_KEY_OPERATION_VALUES
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
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._hash_alg: Any = None
        self._curve: Any = None
        self._peer_public_key: Any = None

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

        if self._alg == -25:
            self._hash_alg = hashes.SHA256()
            self._curve = ec.SECP256R1()
            if -1 in self.unprotected:
                self._peer_public_key = COSEKey.new(self.unprotected[-1])
        elif self._alg == -26:
            self._hash_alg = hashes.SHA512()
            self._curve = ec.SECP521R1()
            if -1 in self.unprotected:
                self._peer_public_key = COSEKey.new(self.unprotected[-1])
        elif self._alg == -27:
            self._hash_alg = hashes.SHA256()
            self._curve = ec.SECP256R1()
            if -2 in self.unprotected:
                self._peer_public_key = COSEKey.new(self.unprotected[-2])
        elif self._alg == -28:
            self._hash_alg = hashes.SHA512()
            self._curve = ec.SECP521R1()
            if -2 in self.unprotected:
                self._peer_public_key = COSEKey.new(self.unprotected[-2])
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with HKDF: {self._alg}.")

    def derive_key(
        self,
        context: Union[List[Any], Dict[str, Any]],
        material: bytes = b"",
        private_key: Optional[COSEKeyInterface] = None,
        public_key: Optional[COSEKeyInterface] = None,
    ) -> COSEKeyInterface:

        if isinstance(context, dict):
            alg = self._alg if isinstance(self._alg, int) else 0
            context = to_cis(context, recipient_alg=alg)
        else:
            self._validate_context(context)

        if public_key and not isinstance(public_key.key, EllipticCurvePublicKey):
            raise ValueError("public_key should be EC public key.")

        # Derive key.
        public_key = public_key if public_key else self._peer_public_key
        priv_key = (
            private_key.key if private_key else ec.generate_private_key(self._curve)
        )
        shared_key = priv_key.exchange(ec.ECDH(), public_key.key)
        hkdf = HKDF(
            algorithm=self._hash_alg,
            length=COSE_KEY_LEN[context[0]] // 8,
            salt=None,
            info=self._dumps(context),
        )
        key = hkdf.derive(shared_key)
        self._unprotected[4] = self._kid if self._kid else public_key.kid
        derived = COSEKey.from_symmetric_key(
            key, alg=context[0], kid=self._unprotected[4]
        )
        if self._alg in [-25, -26]:
            # ECDH-ES
            self._unprotected[-1] = EC2Key.to_cose_key(priv_key.public_key())
        else:  # in [-27, -28]
            # ECDH-SS
            self._unprotected[-2] = EC2Key.to_cose_key(priv_key.public_key())
        return derived
