from typing import Any, Dict

import cryptography
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..const import JWK_ELLIPTIC_CURVES
from ..exceptions import EncodeError, VerifyError
from .signature import SignatureKey


class OKPKey(SignatureKey):
    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)
        self._public_key: Any = None
        self._private_key: Any = None

        # Validate kty.
        if params[1] != 1:
            raise ValueError("kty(1) should be OKP(1).")

        # Validate x and y.
        if -2 not in params:
            raise ValueError("x(-2) not found.")
        if not isinstance(params[-2], bytes):
            raise ValueError("x(-2) should be bytes(bstr).")
        self._x = params[-2]
        self._d = None

        # Validate or Complement alg.
        if not self._alg:
            self._alg = -8  # EdDSA
        else:
            if self._alg != -8:
                raise ValueError(f"OKP algorithm mismatch: {params[3]}.")

        # Validate crv.
        if -1 not in params:
            raise ValueError("crv(-1) not found.")
        if not isinstance(params[-1], int) and not isinstance(params[-1], str):
            raise ValueError("crv(-1) should be int or str(tstr).")
        self._crv: int = (
            params[-1]
            if isinstance(params[-1], int)
            else JWK_ELLIPTIC_CURVES[params[-1]]
        )
        if self._crv not in [4, 5, 6, 7]:
            raise ValueError(f"Unsupported or unknown curve({self._crv}) for OKP.")

        try:
            if -4 not in params:
                if self._crv == 4:  # X25519
                    self._public_key = X25519PublicKey.from_public_bytes(self._x)
                elif self._crv == 5:  # X448
                    self._public_key = X448PublicKey.from_public_bytes(self._x)
                elif self._crv == 6:  # Ed25519
                    self._public_key = Ed25519PublicKey.from_public_bytes(self._x)
                else:  # self._crv == 7 (Ed448)
                    self._public_key = Ed448PublicKey.from_public_bytes(self._x)
                return
        except ValueError as err:
            raise ValueError("Invalid key parameter.") from err

        if not isinstance(params[-4], bytes):
            raise ValueError("d(-4) should be bytes(bstr).")

        try:
            self._d = params[-4]
            if self._crv == 4:  # X25519
                self._private_key = X25519PrivateKey.from_private_bytes(self._d)
            elif self._crv == 5:  # X448
                self._private_key = X448PrivateKey.from_private_bytes(self._d)
            elif self._crv == 6:  # Ed25519
                self._private_key = Ed25519PrivateKey.from_private_bytes(self._d)
            else:  # self._crv == 7 (Ed448)
                self._private_key = Ed448PrivateKey.from_private_bytes(self._d)
        except ValueError as err:
            raise ValueError("Invalid key parameter.") from err
        return

    @property
    def crv(self) -> int:
        return self._crv

    def to_dict(self) -> Dict[int, Any]:
        res = super().to_dict()
        res[-1] = self._crv
        res[-2] = self._x
        if self._d:
            res[-4] = self._d
        return res

    def sign(self, msg: bytes) -> bytes:
        if self._public_key:
            raise ValueError("Public key cannot be used for signing.")
        try:
            return self._private_key.sign(msg)
        except Exception as err:
            raise EncodeError("Failed to sign.") from err

    def verify(self, msg: bytes, sig: bytes):
        try:
            if self._private_key:
                self._private_key.public_key().verify(sig, msg)
            else:
                self._public_key.verify(sig, msg)
        except cryptography.exceptions.InvalidSignature as err:
            raise VerifyError("Failed to verify.") from err
