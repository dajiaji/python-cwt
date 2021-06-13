from typing import Any, Dict, List, Optional, Union

import cryptography
from cryptography.hazmat.primitives import hashes
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ..const import (  # COSE_KEY_LEN,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_ES,
    COSE_ALGORITHMS_SIG_OKP,
    COSE_KEY_LEN,
    COSE_KEY_OPERATION_VALUES,
    COSE_KEY_TYPES,
)
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import EncodeError, VerifyError
from ..utils import to_cis
from .symmetric import AESCCMKey, AESGCMKey, ChaCha20Key


class OKPKey(COSEKeyInterface):

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
        self._hash_alg: Any = None
        self._x = None
        self._d = None

        # Validate kty.
        if params[1] != 1:
            raise ValueError("kty(1) should be OKP(1).")

        # Validate crv.
        if -1 not in params:
            raise ValueError("crv(-1) not found.")
        self._crv = params[-1]
        if not isinstance(self._crv, int):
            raise ValueError("crv(-1) should be int.")
        if self._crv not in [4, 5, 6, 7]:
            raise ValueError(f"Unsupported or unknown crv(-1) for OKP: {self._crv}.")
        if self._crv in [4, 5]:
            if not self._alg:
                raise ValueError("X25519/X448 needs alg explicitly.")
            if self._alg in [-25, -27]:
                self._hash_alg = hashes.SHA256
            elif self._alg in [-26, -28]:
                self._hash_alg = hashes.SHA512
            else:
                raise ValueError(
                    f"Unsupported or unknown alg used with X25519/X448: {self._alg}."
                )

        # Validate alg and key_ops.
        if self._key_ops:
            if set(self._key_ops) & set([3, 4, 5, 6, 9, 10]):
                raise ValueError("Unknown or not permissible key_ops(4) for OKP.")
        else:
            if self._crv in [4, 5]:
                self._key_ops = [7, 8] if -4 in params else []
            else:  # self._crv in [6, 7]
                self._key_ops = [1, 2] if -4 in params else [2]
        if self._alg:
            if self._alg in COSE_ALGORITHMS_SIG_OKP.values():
                if -4 in params:
                    # private key for signing.
                    if not (set(self._key_ops) & set([1, 2])):
                        raise ValueError("Invalid key_ops for signing key.")
                    if set(self._key_ops) & set([7, 8]):
                        raise ValueError(
                            "Signing key should not be used for key derivation."
                        )
                else:
                    # public key for signing.
                    if 2 not in self._key_ops or len(self._key_ops) != 1:
                        raise ValueError("Invalid key_ops for public key.")
            elif self._alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.values():
                if -4 in params:
                    # private key for key derivation.
                    if not (set(self._key_ops) & set([7, 8])):
                        raise ValueError("Invalid key_ops for key derivation.")
                    if set(self._key_ops) & set([1, 2]):
                        raise ValueError(
                            "Private key for ECDHE should not be used for signing."
                        )
                else:
                    # public key for key derivation.
                    if self._key_ops:
                        raise ValueError(
                            "Public key for ECDHE should not have key_ops."
                        )
            else:
                raise ValueError(f"Unsupported or unknown alg(3) for OKP: {self._alg}.")
        else:
            if -4 in params:
                # private key.
                if set(self._key_ops) & set([1, 2]):
                    # private key for signing.
                    if set(self._key_ops) & set([7, 8]):
                        raise ValueError(
                            "OKP private key should not be used for both signing and key derivation."
                        )
                    self._alg = -8  # EdDSA
            else:
                # public key.
                if 2 in self._key_ops:
                    if len(self._key_ops) > 1:
                        raise ValueError("Invalid key_ops for public key.")
                else:
                    raise ValueError("Invalid key_ops for public key.")

        if self._alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_ES.values():
            if -2 not in params:
                return

        # Validate x.
        if -2 not in params:
            raise ValueError("x(-2) not found.")
        if not isinstance(params[-2], bytes):
            raise ValueError("x(-2) should be bytes(bstr).")
        self._x = params[-2]
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
                self._key = self._public_key
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
            self._key = self._private_key
        except ValueError as err:
            raise ValueError("Invalid key parameter.") from err
        return

    @staticmethod
    def to_cose_key(
        k: Union[
            Ed448PrivateKey,
            Ed448PublicKey,
            Ed25519PrivateKey,
            Ed25519PublicKey,
            X448PrivateKey,
            X448PublicKey,
            X25519PrivateKey,
            X25519PublicKey,
        ]
    ) -> Dict[int, Any]:
        cose_key: Dict[int, Any] = {}

        cose_key[1] = COSE_KEY_TYPES["OKP"]
        cose_key[-1] = 6  # Ed25519
        if isinstance(k, Ed25519PublicKey) or isinstance(k, Ed25519PrivateKey):
            cose_key[-1] = 6  # Ed25519
            if isinstance(k, Ed25519PublicKey):
                cose_key[-2] = k.public_bytes(Encoding.Raw, PublicFormat.Raw)
            else:
                cose_key[-2] = k.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                cose_key[-4] = k.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
        elif isinstance(k, Ed448PublicKey) or isinstance(k, Ed448PrivateKey):
            cose_key[-1] = 7  # Ed448
            if isinstance(k, Ed448PublicKey):
                cose_key[-2] = k.public_bytes(Encoding.Raw, PublicFormat.Raw)
            else:
                cose_key[-2] = k.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                cose_key[-4] = k.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
        elif isinstance(k, X25519PublicKey) or isinstance(k, X25519PrivateKey):
            cose_key[-1] = 4  # X25519
            if isinstance(k, X25519PublicKey):
                cose_key[-2] = k.public_bytes(Encoding.Raw, PublicFormat.Raw)
            else:
                cose_key[-2] = k.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                cose_key[-4] = k.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
        elif isinstance(k, X448PublicKey) or isinstance(k, X448PrivateKey):
            cose_key[-1] = 5  # X448
            if isinstance(k, X448PublicKey):
                cose_key[-2] = k.public_bytes(Encoding.Raw, PublicFormat.Raw)
            else:
                cose_key[-2] = k.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                cose_key[-4] = k.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
        else:
            raise ValueError("Unsupported or unknown key for OKP.")
        return cose_key

    @property
    def key(
        self,
    ) -> Union[
        Ed448PrivateKey,
        Ed448PublicKey,
        Ed25519PrivateKey,
        Ed25519PublicKey,
        X448PrivateKey,
        X448PublicKey,
        X25519PrivateKey,
        X25519PublicKey,
    ]:
        return self._key

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
        if not isinstance(public_key.key, X25519PublicKey) and not isinstance(
            public_key.key, X448PublicKey
        ):
            raise ValueError("public_key should be x25519/x448 public key.")
        # if self._alg not in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.values():
        #     raise ValueError(f"Invalid alg for key derivation: {self._alg}.")

        # Validate context information.
        if isinstance(context, dict):
            context = to_cis(context, self._alg)
        else:
            self._validate_context(context)

        # Derive key.
        if self._private_key:
            self._key = self._private_key
        else:
            self._key = (
                X25519PrivateKey.generate()
                if self._crv == 4
                else X448PrivateKey.generate()
            )
        shared_key = self._key.exchange(public_key.key)
        hkdf = HKDF(
            algorithm=self._hash_alg(),
            length=COSE_KEY_LEN[context[0]] // 8,
            salt=None,
            info=self._dumps(context),
        )
        cose_key = {
            1: 4,
            3: context[0],
            -1: hkdf.derive(shared_key),
        }
        if cose_key[3] in [1, 2, 3]:
            return AESGCMKey(cose_key)
        if cose_key[3] in [10, 11, 12, 13, 30, 31, 32, 33]:
            return AESCCMKey(cose_key)
        # cose_key[3] == 24:
        return ChaCha20Key(cose_key)
