from typing import Any, Dict, List, Optional, Union

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..const import (
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_ES,
    COSE_ALGORITHMS_SIG_EC2,
    COSE_KEY_LEN,
    COSE_KEY_OPERATION_VALUES,
    COSE_KEY_TYPES,
)
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import EncodeError, VerifyError
from ..utils import i2osp, os2ip, to_cis
from .asymmetric import AsymmetricKey
from .symmetric import AESCCMKey, AESGCMKey, ChaCha20Key, HMACKey


class EC2Key(AsymmetricKey):

    _ACCEPTABLE_PUBLIC_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["verify"],
    ]

    _ACCEPTABLE_PRIVATE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["sign"],
        COSE_KEY_OPERATION_VALUES["verify"],
        COSE_KEY_OPERATION_VALUES["deriveKey"],
        COSE_KEY_OPERATION_VALUES["deriveBits"],
    ]

    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)
        self._public_key: Any = None
        self._private_key: Any = None
        self._crv_obj: Any = None
        self._hash_alg: Any = None

        # Validate kty.
        if self._kty != 2:
            raise ValueError("kty(1) should be EC2(2).")

        # Validate crv.
        if -1 not in params:
            raise ValueError("crv(-1) not found.")
        self._crv = params[-1]
        if not isinstance(self._crv, int):
            raise ValueError("crv(-1) should be int.")
        if self._crv == 1:  # P-256
            self._crv_obj = ec.SECP256R1()
            self._hash_alg = hashes.SHA256
        elif self._crv == 2:  # P-384
            self._crv_obj = ec.SECP384R1()
            self._hash_alg = hashes.SHA384
        elif self._crv == 3:  # P-521
            self._crv_obj = ec.SECP521R1()
            self._hash_alg = hashes.SHA512
        elif self._crv == 8:  # secp256k1
            self._crv_obj = ec.SECP256K1()
            self._hash_alg = hashes.SHA256
        else:
            raise ValueError(f"Unsupported or unknown crv(-1) for EC2: {self._crv}.")

        # Validate alg and key_ops.
        if self._key_ops:
            if set(self._key_ops) & set([3, 4, 5, 6, 9, 10]):
                raise ValueError("Unknown or not permissible key_ops(4) for EC2.")

        if not self._alg and not self._key_ops:
            # raise ValueError("EC2 private key should be identifiable to the algorithm.")
            if -4 in params:
                self._key_ops = [1, 2]
            else:
                self._key_ops = [2]
        if self._alg:
            if self._alg in COSE_ALGORITHMS_SIG_EC2.values():
                if self._key_ops:
                    if -4 in params:
                        # private key for signing.
                        if not (set(self._key_ops) & set([1, 2])):
                            raise ValueError("Invalid key_ops for signing key.")
                        if set(self._key_ops) & set([7, 8]):
                            raise ValueError("Signing key should not be used for key derivation.")
                    else:
                        # public key for signing.
                        if 2 not in self._key_ops or len(self._key_ops) != 1:
                            raise ValueError("Invalid key_ops for public key.")
                else:
                    if -4 in params:
                        # private key for signing.
                        self._key_ops = [1, 2]
                    else:
                        # public key for signing.
                        self._key_ops = [2]

            elif self._alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.values():
                if self._key_ops:
                    if -4 in params:
                        # private key for key derivation.
                        if not (set(self._key_ops) & set([7, 8])):
                            raise ValueError("Invalid key_ops for key derivation.")
                        if set(self._key_ops) & set([1, 2]):
                            raise ValueError("ECDHE key should not be used for signing.")
                    else:
                        # public key for key derivation.
                        raise ValueError("Public key for ECDHE should not have key_ops.")
                else:
                    if -2 not in params and -3 not in params:
                        # private key for key derivation.
                        self._key_ops = [7, 8]
            else:
                raise ValueError(f"Unsupported or unknown alg(3) for EC2: {self._alg}.")
        else:
            if -4 in params:
                # private key.
                if set(self._key_ops) & set([1, 2]):
                    # private key for signing.
                    if set(self._key_ops) & set([7, 8]):
                        raise ValueError("EC2 Private key should not be used for both signing and key derivation.")
                    if self._crv == 1:
                        self._alg = -7  # ES256
                    elif self._crv == 2:
                        self._alg = -35  # ES384
                    elif self._crv == 3:
                        self._alg = -36  # ES512
                    else:  # self._crv == 8
                        self._alg = -47  # ES256K
            else:
                # public key.
                if 2 in self._key_ops:
                    if len(self._key_ops) > 1:
                        raise ValueError("Invalid key_ops for public key.")
                else:
                    raise ValueError("Invalid key_ops for public key.")

        if self._alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_ES.values():
            if -2 not in params and -3 not in params:
                return

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
        if self._crv == 1:  # P-256
            if not (len(self._x) == len(self._y) == 32):
                raise ValueError("Coords should be 32 bytes for crv P-256.")
        elif self._crv == 2:  # P-384
            if not (len(self._x) == len(self._y) == 48):
                raise ValueError("Coords should be 48 bytes for crv P-384.")
        elif self._crv == 3:  # P-521
            if not (len(self._x) == len(self._y) == 66):
                raise ValueError("Coords should be 66 bytes for crv P-521.")
        else:  # self._crv == 8 (secp256k1)
            if not (len(self._x) == len(self._y) == 32):
                raise ValueError("Coords should be 32 bytes for crv secp256k1.")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(self._x, byteorder="big"),
            y=int.from_bytes(self._y, byteorder="big"),
            curve=self._crv_obj,
        )

        # Validate d.
        self._d = None
        if -4 not in params:
            self._public_key = public_numbers.public_key()
            self._key = self._public_key
            return

        if not isinstance(params[-4], bytes):
            raise ValueError("d(-4) should be bytes(bstr).")
        self._d = params[-4]
        if len(self._d) != len(self._x):
            raise ValueError(f"d(-4) should be {len(self._x)} bytes for curve {self._crv}")
        try:
            self._private_key = ec.EllipticCurvePrivateNumbers(
                int.from_bytes(self._d, byteorder="big"), public_numbers
            ).private_key()
            self._key = self._private_key
        except Exception as err:
            raise ValueError("Invalid private key.") from err
        return

    @staticmethod
    def to_cose_key(k: Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> Dict[int, Any]:
        key_len: int = 32
        cose_key: Dict[int, Any] = {}

        cose_key[1] = COSE_KEY_TYPES["EC2"]
        if not hasattr(k, "curve"):
            raise ValueError("Unsupported or unknown key for EC2.")
        if k.curve.name == "secp256r1":
            cose_key[-1] = 1
        elif k.curve.name == "secp384r1":
            cose_key[-1] = 2
            key_len = 48
        elif k.curve.name == "secp521r1":
            cose_key[-1] = 3
            key_len = 66
        else:  # k.curve.name == "secp256k1":
            cose_key[-1] = 8
        if isinstance(k, EllipticCurvePublicKey):
            cose_key[-2] = k.public_numbers().x.to_bytes(key_len, byteorder="big")
            cose_key[-3] = k.public_numbers().y.to_bytes(key_len, byteorder="big")
            return cose_key
        cose_key[-2] = k.public_key().public_numbers().x.to_bytes(key_len, byteorder="big")
        cose_key[-3] = k.public_key().public_numbers().y.to_bytes(key_len, byteorder="big")
        cose_key[-4] = k.private_numbers().private_value.to_bytes(key_len, byteorder="big")
        return cose_key

    @property
    def key(self) -> Union[EllipticCurvePublicKey, EllipticCurvePrivateKey]:
        return self._key

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
                self._private_key.public_key().verify(der_sig, msg, ec.ECDSA(self._hash_alg()))
            else:
                der_sig = self._os_to_der(self._public_key.curve.key_size, sig)
                self._public_key.verify(der_sig, msg, ec.ECDSA(self._hash_alg()))
        except cryptography.exceptions.InvalidSignature as err:
            raise VerifyError("Failed to verify.") from err
        except ValueError as err:
            raise VerifyError("Invalid signature.") from err

    def derive_key(
        self,
        context: Union[List[Any], Dict[str, Any]],
        material: bytes = b"",
        public_key: Optional[COSEKeyInterface] = None,
    ) -> COSEKeyInterface:

        if self._public_key:
            raise ValueError("Public key cannot be used for key derivation.")
        if not public_key:
            raise ValueError("public_key should be set.")
        if not isinstance(public_key.key, EllipticCurvePublicKey):
            raise ValueError("public_key should be elliptic curve public key.")
        if self._alg not in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.values():
            raise ValueError(f"Invalid alg for key derivation: {self._alg}.")

        # Validate context information.
        if isinstance(context, dict):
            context = to_cis(context, self._alg)
        else:
            self._validate_context(context)

        # Derive key.
        self._key = self._private_key if self._private_key else ec.generate_private_key(self._crv_obj)
        shared_key = self._key.exchange(ec.ECDH(), public_key.key)
        hkdf = HKDF(
            algorithm=self._hash_alg(),
            length=COSE_KEY_LEN[context[0]] // 8,
            salt=None,
            info=self._dumps(context),
        )
        # return COSEKey.from_symmetric_key(hkdf.derive(shared_key), alg=context[0])
        cose_key = {
            1: 4,
            3: context[0],
            -1: hkdf.derive(shared_key),
        }
        if cose_key[3] in [1, 2, 3]:
            return AESGCMKey(cose_key)
        if cose_key[3] in [4, 5, 6, 7]:
            return HMACKey(cose_key)
        if cose_key[3] in [10, 11, 12, 13, 30, 31, 32, 33]:
            return AESCCMKey(cose_key)
        # cose_key[3] == 24:
        return ChaCha20Key(cose_key)

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
