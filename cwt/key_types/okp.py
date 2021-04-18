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

from ..cose_key import COSEKey
from ..exceptions import EncodeError, VerifyError


class OKPKey(COSEKey):
    """"""

    def __init__(self, cose_key: Dict[int, Any]):
        """"""
        super().__init__(cose_key)
        self._public_key: Any = None
        self._private_key: Any = None

        # Validate kty.
        if 1 not in cose_key:
            raise ValueError("kty(1) not found.")
        if not isinstance(cose_key[1], int) and not isinstance(cose_key[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if cose_key[1] != 1:
            raise ValueError("kty(1) should be OKP(1).")

        # Validate x and y.
        if -2 not in cose_key:
            raise ValueError("x(-2) not found.")
        if not isinstance(cose_key[-2], bytes):
            raise ValueError("x(-2) should be bytes(bstr).")
        x = cose_key[-2]

        # Validate crv.
        if -1 not in cose_key:
            raise ValueError("crv(-1) not found.")
        if not isinstance(cose_key[-1], int) and not isinstance(cose_key[-1], str):
            raise ValueError("crv(-1) should be int or str(tstr).")
        crv = cose_key[-1]

        try:
            if -4 not in cose_key:
                if crv == 4:  # X25519
                    self._public_key = X25519PublicKey.from_public_bytes(x)
                elif crv == 5:  # X448
                    self._public_key = X448PublicKey.from_public_bytes(x)
                elif crv == 6:  # Ed25519
                    self._public_key = Ed25519PublicKey.from_public_bytes(x)
                elif crv == 7:  # Ed448
                    self._public_key = Ed448PublicKey.from_public_bytes(x)
                else:
                    raise ValueError(f"Unknown curve: {crv}")
                return
            if not isinstance(cose_key[-4], bytes):
                raise ValueError("d(-4) should be bytes(bstr).")
            d = cose_key[-4]
            if crv == 4:  # X25519
                self._private_key = X25519PrivateKey.from_private_bytes(d)
            elif crv == 5:  # X448
                self._private_key = X448PrivateKey.from_private_bytes(d)
            elif crv == 6:  # Ed25519
                self._private_key = Ed25519PrivateKey.from_private_bytes(d)
            elif crv == 7:  # Ed448
                self._private_key = Ed448PrivateKey.from_private_bytes(d)
            else:
                raise ValueError(f"Unknown curve: {crv}")

        except ValueError as err:
            raise ValueError("Invalid key parameter") from err
        return

    def sign(self, msg: bytes) -> bytes:
        """"""
        try:
            if self._public_key:
                raise ValueError("Public key cannot be used for signing.")
            return self._private_key.sign(msg)
        except Exception as err:
            raise EncodeError("Failed to sign.") from err

    def verify(self, msg: bytes, sig: bytes):
        """"""
        try:
            if self._private_key:
                self._private_key.public_key().verify(sig, msg)
            else:
                self._public_key.verify(sig, msg)
        except cryptography.exceptions.InvalidSignature as err:
            raise VerifyError("Failed to verify.") from err
