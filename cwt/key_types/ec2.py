from typing import Any, Dict

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ..cose_key import COSEKey
from ..exceptions import InvalidSignature
from ..utils import i2osp, os2ip


class EC2Key(COSEKey):
    """"""

    def __init__(self, cose_key: Dict[int, Any]):
        """"""
        super().__init__(cose_key)
        self._public_key: Any = None
        self._private_key: Any = None
        self._hash_alg: Any = None

        # Validate kty.
        if 1 not in cose_key:
            raise ValueError("kty(1) not found.")
        if not isinstance(cose_key[1], int) and not isinstance(cose_key[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if cose_key[1] != 2:
            raise ValueError("kty(1) should be EC2(2).")

        # Validate x and y.
        if -2 not in cose_key:
            raise ValueError("x(-2) not found.")
        if not isinstance(cose_key[-2], bytes):
            raise ValueError("x(-2) should be bytes(bstr).")
        if -3 not in cose_key:
            raise ValueError("y(-3) not found.")
        if not isinstance(cose_key[-3], bytes):
            raise ValueError("y(-3) should be bytes(bstr).")
        x = cose_key[-2]
        y = cose_key[-3]

        # Validate crv.
        if -1 not in cose_key:
            raise ValueError("crv(-1) not found.")
        if not isinstance(cose_key[-1], int) and not isinstance(cose_key[-1], str):
            raise ValueError("crv(-1) should be int or str(tstr).")
        crv = cose_key[-1]
        crv_obj: Any
        if crv == 1:  # P-256
            if len(x) == len(y) == 32:
                crv_obj = ec.SECP256R1()
                self._hash_alg = hashes.SHA256
            else:
                raise ValueError("Coords should be 32 bytes for crv P-256")
        elif crv == 2:  # P-384
            if len(x) == len(y) == 48:
                crv_obj = ec.SECP384R1()
                self._hash_alg = hashes.SHA384
            else:
                raise ValueError("Coords should be 48 bytes for crv P-384")
        elif crv == 3:  # P-521
            if len(x) == len(y) == 66:
                crv_obj = ec.SECP521R1()
                self._hash_alg = hashes.SHA512
            else:
                raise ValueError("Coords should be 66 bytes for crv P-521")
        elif crv == 8:  # secp256k1
            if len(x) == len(y) == 32:
                crv_obj = ec.SECP256K1()
                self._hash_alg = hashes.SHA256
            else:
                raise ValueError("Coords should be 32 bytes for crv secp256k1")
        else:
            raise ValueError(f"Unsupported or unknown crv: {crv}")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, byteorder="big"),
            y=int.from_bytes(y, byteorder="big"),
            curve=crv_obj,
        )

        # Validate d.
        if -4 not in cose_key:
            self._public_key = public_numbers.public_key()
            return

        if not isinstance(cose_key[-4], bytes):
            raise ValueError("d(-4) should be bytes(bstr).")
        d = cose_key[-4]
        if len(d) != len(x):
            raise ValueError("d(-4) should be {} bytes for curve {}", len(x), crv)
        self._private_key = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(d, byteorder="big"), public_numbers
        ).private_key()
        return

    def sign(self, msg: bytes) -> bytes:
        """"""
        try:
            if self._public_key:
                raise ValueError("Public key cannot be used for signing.")
            sig = self._private_key.sign(msg, ec.ECDSA(self._hash_alg()))
            return self._der_to_os(self._private_key.curve.key_size, sig)
        except ValueError as err:
            raise InvalidSignature("Failed to sign.") from err

    def verify(self, msg: bytes, sig: bytes):
        """"""
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
            raise InvalidSignature("Failed to verify.") from err
        except ValueError as err:
            raise InvalidSignature("Invalid signature.") from err

    def _der_to_os(self, key_size: int, sig: bytes) -> bytes:
        """"""
        num_bytes = (key_size + 7) // 8
        r, s = decode_dss_signature(sig)
        return i2osp(r, num_bytes) + i2osp(s, num_bytes)

    def _os_to_der(self, key_size: int, sig: bytes) -> bytes:
        """"""
        num_bytes = (key_size + 7) // 8
        if len(sig) != 2 * num_bytes:
            raise ValueError("Invalid signature.")
        r = os2ip(sig[:num_bytes])
        s = os2ip(sig[num_bytes:])
        return encode_dss_signature(r, s)
