from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
)

from ..const import COSE_ALGORITHMS_RSA, COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..exceptions import EncodeError, VerifyError


class RSAKey(COSEKey):

    _ACCEPTABLE_PUBLIC_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["verify"],
    ]

    _ACCEPTABLE_PRIVATE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["sign"],
        COSE_KEY_OPERATION_VALUES["verify"],
    ]

    def __init__(self, cose_key: Dict[int, Any]):
        super().__init__(cose_key)

        self._key: Any = None
        self._hash: Any = None
        self._padding: Any = None

        # Validate kty.
        if cose_key[1] != 3:
            raise ValueError("kty(1) should be RSA(3).")

        # Validate alg.
        if 3 not in cose_key:
            raise ValueError("alg(3) not found.")
        if cose_key[3] not in COSE_ALGORITHMS_RSA.values():
            raise ValueError(f"Unsupported or unknown alg(3) for RSA: {cose_key[3]}.")
        if cose_key[3] == -259 or cose_key[3] == -39:
            self._hash = hashes.SHA512
        elif cose_key[3] == -258 or cose_key[3] == -38:
            self._hash = hashes.SHA384
        elif cose_key[3] == -257 or cose_key[3] == -37:
            self._hash = hashes.SHA256
        else:
            raise ValueError(f"Unsupported or unknown alg(3) for RSA: {cose_key[3]}.")
        if cose_key[3] in [-37, -38, -39]:
            self._padding = padding.PSS(
                mgf=padding.MGF1(self._hash()), salt_length=padding.PSS.MAX_LENGTH
            )
        else:
            self._padding = padding.PKCS1v15()

        # Validate key_ops.
        if -3 not in cose_key:  # the RSA private exponent d.
            if 4 not in self._object or not self._object[4]:
                self._object[4] = RSAKey._ACCEPTABLE_PUBLIC_KEY_OPS
            else:
                prohibited = [
                    ops
                    for ops in self._object[4]
                    if ops not in RSAKey._ACCEPTABLE_PUBLIC_KEY_OPS
                ]
                if prohibited:
                    raise ValueError(
                        f"Unknown or not permissible key_ops(4) for RSAKey: {prohibited[0]}."
                    )
        else:
            if 4 not in self._object or not self._object[4]:
                self._object[4] = RSAKey._ACCEPTABLE_PRIVATE_KEY_OPS
            else:
                prohibited = [
                    ops
                    for ops in self._object[4]
                    if ops not in RSAKey._ACCEPTABLE_PRIVATE_KEY_OPS
                ]
                if prohibited:
                    raise ValueError(
                        f"Unknown or not permissible key_ops(4) for RSAKey: {prohibited[0]}."
                    )

        # Validate RSA specific parameters.
        if -1 not in cose_key or not isinstance(cose_key[-1], bytes):
            raise ValueError("n(-1) should be set as bytes.")
        if -2 not in cose_key or not isinstance(cose_key[-2], bytes):
            raise ValueError("e(-2) should be set as bytes.")

        public_numbers = RSAPublicNumbers(
            n=int.from_bytes(cose_key[-1], "big"),
            e=int.from_bytes(cose_key[-2], "big"),
        )
        if -3 not in cose_key:  # the RSA private exponent d.
            private_props = [p for p in cose_key.keys() if p in [-4, -5, -6, -7, -8]]
            if private_props:
                raise ValueError(
                    f"RSA public key should not have private parameter: {private_props[0]}."
                )
            self._key = public_numbers.public_key()
            return

        if -3 not in cose_key or not isinstance(cose_key[-3], bytes):
            raise ValueError("d(-3) should be set as bytes.")
        if -4 not in cose_key or not isinstance(cose_key[-4], bytes):
            raise ValueError("p(-4) should be set as bytes.")
        if -5 not in cose_key or not isinstance(cose_key[-5], bytes):
            raise ValueError("q(-5) should be set as bytes.")
        if -6 not in cose_key or not isinstance(cose_key[-6], bytes):
            raise ValueError("dP(-6) should be set as bytes.")
        if -7 not in cose_key or not isinstance(cose_key[-7], bytes):
            raise ValueError("dQ(-7) should be set as bytes.")
        if -8 not in cose_key or not isinstance(cose_key[-8], bytes):
            raise ValueError("qInv(-8) should be set as bytes.")

        private_numbers = RSAPrivateNumbers(
            d=int.from_bytes(cose_key[-3], "big"),
            p=int.from_bytes(cose_key[-4], "big"),
            q=int.from_bytes(cose_key[-5], "big"),
            dmp1=int.from_bytes(cose_key[-6], "big"),
            dmq1=int.from_bytes(cose_key[-7], "big"),
            iqmp=int.from_bytes(cose_key[-8], "big"),
            public_numbers=public_numbers,
        )
        self._key = private_numbers.private_key()
        return

    def sign(self, msg: bytes) -> bytes:
        if isinstance(self._key, RSAPublicKey):
            raise ValueError("Public key cannot be used for signing.")
        try:
            return self._key.sign(msg, self._padding, self._hash())
        except Exception as err:
            raise EncodeError("Failed to sign.") from err

    def verify(self, msg: bytes, sig: bytes):
        try:
            if isinstance(self._key, RSAPublicKey):
                self._key.verify(sig, msg, self._padding, self._hash())
            else:
                self._key.public_key().verify(sig, msg, self._padding, self._hash())
        except Exception as err:
            raise VerifyError("Failed to verify.") from err
