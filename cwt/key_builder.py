import json
from typing import Any, Dict, Optional, Union

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from .const import COSE_ALGORITHMS_SYMMETRIC, COSE_KEY_TYPES
from .cose_key import COSEKey
from .key_types.ec2 import EC2Key
from .key_types.okp import OKPKey
from .key_types.symmetric import AESCCMKey, HMACKey


class KeyBuilder:
    """"""

    COSE_KEY_COMMON_PARAMS = {
        "kty": 1,  # tstr / int
        "kid": 2,  # bstr
        "alg": 3,  # tstr / int
        "key_ops": 4,  # [+ (tstr / int)]
        "base_iv": 5,  # bstr
        # * label => values
    }

    COSE_KEY_OPERATION_VALUES = {
        "sign": 1,
        "verify": 2,
        "encrypt": 3,
        "decrypt": 4,
        "wrap_key": 5,
        "unwrap_key": 6,
        "derive_key": 7,
        "derive_bits": 8,
        "MAC_create": 9,
        "MAC_verify": 10,
    }

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """"""
        self._options = options
        return

    def from_symmetric_key(
        self, key: Union[bytes, str], alg: str = "HMAC 256/256"
    ) -> COSEKey:
        """"""
        if isinstance(key, str):
            key = key.encode("utf-8")
        alg_id = COSE_ALGORITHMS_SYMMETRIC.get(alg, None)
        if not alg_id:
            raise ValueError("Unsupported or unknown alg: %s" % alg)

        cose_key = {
            1: 4,  # kty: 'Symmetric'
            3: alg_id,  # alg: int
            -1: key,  # k:   bstr
        }
        if alg_id in [4, 5, 6, 7]:
            return HMACKey(cose_key)
        if alg_id in [10, 11, 12, 13, 30, 31, 32, 33]:
            return AESCCMKey(cose_key)
        raise ValueError("Unsupported or unknown alg(3): %d" % alg_id)

    def from_dict(self, cose_key: Dict[int, Any]) -> COSEKey:
        """"""

        # Validate COSE Key common parameters.
        if 1 not in cose_key:
            raise ValueError("kty(1) not found.")
        if not isinstance(cose_key[1], int) and not isinstance(cose_key[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if cose_key[1] == 1:
            return OKPKey(cose_key)
        if cose_key[1] == 2:
            return EC2Key(cose_key)
        if cose_key[1] == 4:
            if 3 not in cose_key or (
                not isinstance(cose_key[3], int) and not isinstance(cose_key[3], str)
            ):
                raise ValueError("alg(3) should be int str(tstr).")
            if cose_key[3] in [4, 5, 6, 7]:
                return HMACKey(cose_key)
            if cose_key[3] in [10, 11, 12, 13, 30, 31, 32, 33]:
                return AESCCMKey(cose_key)
            raise ValueError(f"Unsupported or unknown alg(3): {cose_key[3]}")
        raise ValueError(f"Unsupported or unknown kty(1): {cose_key[1]}")

    def from_bytes(self, key_data: bytes) -> COSEKey:
        """"""
        cose_key = cbor2.loads(key_data)
        return self.from_dict(cose_key)

    def from_jwk(self, jwk: Union[str, bytes, Dict[str, Any]]) -> COSEKey:
        """"""
        cose_key: Dict[int, Any] = {}
        if not isinstance(jwk, dict):
            jwk = json.loads(jwk)
        # TODO: from JWT to COSE key.
        return self.from_dict(cose_key)

    def from_pem(self, key_data: Union[str, bytes], kid: bytes = b"") -> COSEKey:
        """"""
        if isinstance(key_data, str):
            key_data = key_data.encode("utf-8")
        key_str = key_data.decode("utf-8")
        k: Any = None
        if "BEGIN PUBLIC" in key_str:
            k = load_pem_public_key(key_data)
        elif "BEGIN PRIVATE" in key_str:
            k = load_pem_private_key(key_data, password=None)
        elif "BEGIN EC PRIVATE" in key_str:
            k = load_pem_private_key(key_data, password=None)
        else:
            raise ValueError("Failed to decode PEM.")

        cose_key: Dict[int, Any] = {}
        if isinstance(k, EllipticCurvePrivateKey) or isinstance(
            k, EllipticCurvePublicKey
        ):
            cose_key[1] = COSE_KEY_TYPES["EC2"]
            if k.curve.name == "secp256r1":
                cose_key[3] = cose_key[-1] = 1
            elif k.curve.name == "secp384r1":
                cose_key[3] = cose_key[-1] = 2
            elif k.curve.name == "secp521r1":
                cose_key[3] = cose_key[-1] = 3
            elif k.curve.name == "secp256k1":
                cose_key[3] = cose_key[-1] = 8
            else:
                raise ValueError(f"Unsupported or unknown alg: {k.curve.name}")
            if isinstance(k, EllipticCurvePublicKey):
                cose_key[-2] = k.public_numbers().x.to_bytes(32, byteorder="big")
                cose_key[-3] = k.public_numbers().y.to_bytes(32, byteorder="big")
            else:
                cose_key[-2] = (
                    k.public_key().public_numbers().x.to_bytes(32, byteorder="big")
                )
                cose_key[-3] = (
                    k.public_key().public_numbers().y.to_bytes(32, byteorder="big")
                )
                cose_key[-4] = k.private_numbers().private_value.to_bytes(
                    32, byteorder="big"
                )
        elif isinstance(k, Ed25519PublicKey) or isinstance(k, Ed25519PrivateKey):
            cose_key[1] = COSE_KEY_TYPES["OKP"]
            cose_key[3] = -8  # EdDSA
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
        return self.from_dict(cose_key)


# export
cose_key = KeyBuilder()
