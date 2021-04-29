# import json
from typing import Any, Dict, Optional, Union

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
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
    """
    A :class:`COSEKey <cwt.COSEKey>` Builder.
    """

    _COSE_KEY_COMMON_PARAMS = {
        "kty": 1,  # tstr / int
        "kid": 2,  # bstr
        "alg": 3,  # tstr / int
        "key_ops": 4,  # [+ (tstr / int)]
        "base_iv": 5,  # bstr
        # * label => values
    }

    _COSE_KEY_OPERATION_VALUES = {
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
        """
        Constructor.

        At the current implementation, any ``options`` will be ignored.
        """
        self._options = options
        return

    def from_symmetric_key(
        self,
        key: Union[bytes, str],
        alg: Union[int, str] = "HMAC 256/256",
        kid: Union[bytes, str] = b"",
    ) -> COSEKey:
        """
        Create a COSE key from a symmetric key.

        Args:
            key (Union[bytes, str]): A key bytes or string.
            alg (Union[int, str]): An algorithm label(int) or name(str). Supported ``alg`` are listed
                in `Supported COSE Algorithms <https://python-cwt.readthedocs.io/en/stable/algorithms.html>`_.
            kid (Union[bytes, str]): A key identifier.
        Returns:
            COSEKey: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
        """
        if isinstance(key, str):
            key = key.encode("utf-8")
        alg_id = alg if isinstance(alg, int) else COSE_ALGORITHMS_SYMMETRIC.get(alg, 0)
        if alg_id == 0:
            raise ValueError(f"Unsupported or unknown alg({alg}).")

        cose_key = {
            1: 4,  # kty: 'Symmetric'
            3: alg_id,  # alg: int
            -1: key,  # k:   bstr
        }
        if isinstance(kid, str):
            kid = kid.encode("utf-8")
        if kid:
            cose_key[2] = kid
        if alg_id in [4, 5, 6, 7]:
            return HMACKey(cose_key)
        if alg_id in [10, 11, 12, 13, 30, 31, 32, 33]:
            return AESCCMKey(cose_key)
        raise ValueError(f"Unsupported or unknown alg({alg_id}).")

    def from_dict(self, cose_key: Dict[int, Any]) -> COSEKey:
        """
        Create a COSE key from a CBOR-like dictionary with numeric keys.

        Args:
            cose_key (Dict[int, Any]): A CBOR-like dictionary with numeric keys
                of a COSE key.
        Returns:
            COSEKey: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
        """

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
                raise ValueError("alg(3) should be int or str(tstr).")
            if cose_key[3] in [4, 5, 6, 7]:
                return HMACKey(cose_key)
            if cose_key[3] in [10, 11, 12, 13, 30, 31, 32, 33]:
                return AESCCMKey(cose_key)
            raise ValueError(f"Unsupported or unknown alg(3): {cose_key[3]}.")
        raise ValueError(f"Unsupported or unknown kty(1): {cose_key[1]}.")

    def from_bytes(self, key_data: bytes) -> COSEKey:
        """
        Create a COSE key from CBOR-formatted key data.

        Args:
            key_data (bytes): CBOR-formatted key data.
        Returns:
            COSEKey: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        cose_key = cbor2.loads(key_data)
        return self.from_dict(cose_key)

    def from_jwk(self, jwk: Union[str, bytes, Dict[str, Any]]) -> COSEKey:
        """"""
        raise NotImplementedError
        # cose_key: Dict[int, Any] = {}
        # if not isinstance(jwk, dict):
        #     jwk = json.loads(jwk)
        # # TODO: from JWT to COSE key.
        # return self.from_dict(cose_key)

    def from_pem(
        self, key_data: Union[str, bytes], kid: Union[bytes, str] = b""
    ) -> COSEKey:
        """
        Create a COSE key from PEM-formatted key data.

        Args:
            key_data (bytes): A PEM-formatted key data.
        Returns:
            COSEKey: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
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
        if isinstance(kid, str):
            kid = kid.encode("utf-8")
        if kid:
            cose_key[2] = kid
        if isinstance(k, EllipticCurvePrivateKey) or isinstance(
            k, EllipticCurvePublicKey
        ):
            key_len: int = 32
            cose_key[1] = COSE_KEY_TYPES["EC2"]
            if k.curve.name == "secp256r1":
                cose_key[3] = cose_key[-1] = 1
            elif k.curve.name == "secp384r1":
                cose_key[3] = cose_key[-1] = 2
                key_len = 48
            elif k.curve.name == "secp521r1":
                cose_key[3] = cose_key[-1] = 3
                key_len = 66
            elif k.curve.name == "secp256k1":
                cose_key[3] = cose_key[-1] = 8
            else:
                raise ValueError(f"Unsupported or unknown alg: {k.curve.name}.")
            if isinstance(k, EllipticCurvePublicKey):
                cose_key[-2] = k.public_numbers().x.to_bytes(key_len, byteorder="big")
                cose_key[-3] = k.public_numbers().y.to_bytes(key_len, byteorder="big")
            else:
                cose_key[-2] = (
                    k.public_key().public_numbers().x.to_bytes(key_len, byteorder="big")
                )
                cose_key[-3] = (
                    k.public_key().public_numbers().y.to_bytes(key_len, byteorder="big")
                )
                cose_key[-4] = k.private_numbers().private_value.to_bytes(
                    key_len, byteorder="big"
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
        elif isinstance(k, Ed448PublicKey) or isinstance(k, Ed448PrivateKey):
            cose_key[1] = COSE_KEY_TYPES["OKP"]
            cose_key[3] = -8  # EdDSA
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
            cose_key[1] = COSE_KEY_TYPES["OKP"]
            cose_key[3] = -8  # EdDSA
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
            cose_key[1] = COSE_KEY_TYPES["OKP"]
            cose_key[3] = -8  # EdDSA
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
            raise ValueError("Unsupported or unknown key: {type(k)}.")
        return self.from_dict(cose_key)


# export
cose_key = KeyBuilder()
