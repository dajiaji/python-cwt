from typing import Any, Dict

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ..const import JWK_ELLIPTIC_CURVES
from ..exceptions import EncodeError, VerifyError
from ..utils import i2osp, os2ip
from .signature import SignatureKey


class EC2Key(SignatureKey):
    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)
        self._public_key: Any = None
        self._private_key: Any = None
        self._hash_alg: Any = None

        # Validate kty.
        if params[1] != 2:
            raise ValueError("kty(1) should be EC2(2).")

        # Validate x and y.
        if -2 not in params:
            raise ValueError("x(-2) not found.")
        if not isinstance(params[-2], bytes):
            raise ValueError("x(-2) should be bytes(bstr).")
        if -3 not in params:
            raise ValueError("y(-3) not found.")
        if not isinstance(params[-3], bytes):
            raise ValueError("y(-3) should be bytes(bstr).")
        self._x = params[-2]
        self._y = params[-3]
        self._d = None

        # Validate crv and alg.
        if -1 not in params:
            raise ValueError("crv(-1) not found.")
        if not isinstance(params[-1], int) and not isinstance(params[-1], str):
            raise ValueError("crv(-1) should be int or str(tstr).")
        self._crv: int = (
            params[-1]
            if isinstance(params[-1], int)
            else JWK_ELLIPTIC_CURVES[params[-1]]
        )
        crv_obj: Any
        if self._crv == 1:  # P-256
            if not self._alg:
                self._alg = -7
            else:
                if self._alg != -7:
                    raise ValueError(f"EC2 algorithm mismatch: {params[3]}.")
            if len(self._x) == len(self._y) == 32:
                crv_obj = ec.SECP256R1()
                self._hash_alg = hashes.SHA256
            else:
                raise ValueError("Coords should be 32 bytes for crv P-256.")
        elif self._crv == 2:  # P-384
            if not self._alg:
                self._alg = -35
            else:
                if self._alg != -35:
                    raise ValueError(f"EC2 algorithm mismatch: {params[3]}.")
            if len(self._x) == len(self._y) == 48:
                crv_obj = ec.SECP384R1()
                self._hash_alg = hashes.SHA384
            else:
                raise ValueError("Coords should be 48 bytes for crv P-384.")
        elif self._crv == 3:  # P-521
            if not self._alg:
                self._alg = -36
            else:
                if self._alg != -36:
                    raise ValueError(f"EC2 algorithm mismatch: {params[3]}.")
            if len(self._x) == len(self._y) == 66:
                crv_obj = ec.SECP521R1()
                self._hash_alg = hashes.SHA512
            else:
                raise ValueError("Coords should be 66 bytes for crv P-521.")
        elif self._crv == 8:  # secp256k1
            if not self._alg:
                self._alg = -47
            else:
                if self._alg != -47:
                    raise ValueError(f"EC2 algorithm mismatch: {params[3]}.")
            if len(self._x) == len(self._y) == 32:
                crv_obj = ec.SECP256K1()
                self._hash_alg = hashes.SHA256
            else:
                raise ValueError("Coords should be 32 bytes for crv secp256k1.")
        else:
            raise ValueError(f"Unsupported or unknown crv: {self._crv}.")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(self._x, byteorder="big"),
            y=int.from_bytes(self._y, byteorder="big"),
            curve=crv_obj,
        )

        # Validate d.
        if -4 not in params:
            self._public_key = public_numbers.public_key()
            return

        if not isinstance(params[-4], bytes):
            raise ValueError("d(-4) should be bytes(bstr).")
        self._d = params[-4]
        if len(self._d) != len(self._x):
            raise ValueError(
                f"d(-4) should be {len(self._x)} bytes for curve {self._crv}"
            )
        try:
            self._private_key = ec.EllipticCurvePrivateNumbers(
                int.from_bytes(self._d, byteorder="big"), public_numbers
            ).private_key()
        except Exception as err:
            raise ValueError("Invalid private key.") from err
        return

    @property
    def crv(self) -> int:
        return self._crv

    def to_dict(self) -> Dict[int, Any]:
        res = super().to_dict()
        res[-1] = self._crv
        res[-2] = self._x
        res[-3] = self._y
        if self._d:
            res[-4] = self._d
        return res

    def sign(self, msg: bytes) -> bytes:
        if self._public_key:
            raise ValueError("Public key cannot be used for signing.")
        try:
            sig = self._private_key.sign(msg, ec.ECDSA(self._hash_alg()))
            return self._der_to_os(self._private_key.curve.key_size, sig)
        except Exception as err:
            raise EncodeError("Failed to sign.") from err

    def verify(self, msg: bytes, sig: bytes):
        try:
            if self._private_key:
                der_sig = self._os_to_der(self._private_key.curve.key_size, sig)
                self._private_key.public_key().verify(
                    der_sig, msg, ec.ECDSA(self._hash_alg())
                )
            else:
                der_sig = self._os_to_der(self._public_key.curve.key_size, sig)
                self._public_key.verify(der_sig, msg, ec.ECDSA(self._hash_alg()))
        except cryptography.exceptions.InvalidSignature as err:
            raise VerifyError("Failed to verify.") from err
        except ValueError as err:
            raise VerifyError("Invalid signature.") from err

    def _der_to_os(self, key_size: int, sig: bytes) -> bytes:
        num_bytes = (key_size + 7) // 8
        r, s = decode_dss_signature(sig)
        return i2osp(r, num_bytes) + i2osp(s, num_bytes)

    def _os_to_der(self, key_size: int, sig: bytes) -> bytes:
        num_bytes = (key_size + 7) // 8
        if len(sig) != 2 * num_bytes:
            raise ValueError("Invalid signature.")
        r = os2ip(sig[:num_bytes])
        s = os2ip(sig[num_bytes:])
        return encode_dss_signature(r, s)
