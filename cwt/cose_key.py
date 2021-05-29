import json
from typing import Any, Dict, List, Optional, Union

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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
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

from .algs.ec2 import EC2Key
from .algs.okp import OKPKey
from .algs.rsa import RSAKey
from .algs.symmetric import AESCCMKey, AESGCMKey, ChaCha20Key, HMACKey
from .const import (
    COSE_ALGORITHMS_RSA,
    COSE_ALGORITHMS_SYMMETRIC,
    COSE_KEY_OPERATION_VALUES,
    COSE_KEY_TYPES,
    COSE_NAMED_ALGORITHMS_SUPPORTED,
    JWK_ELLIPTIC_CURVES,
    JWK_OPERATIONS,
    JWK_PARAMS_EC,
    JWK_PARAMS_OKP,
    JWK_PARAMS_RSA,
    JWK_TYPES,
)
from .cose_key_interface import COSEKeyInterface
from .utils import base64url_decode, uint_to_bytes


class COSEKey:
    """
    A :class:`COSEKeyInterface <cwt.COSEKeyInterface>` Builder.
    """

    @staticmethod
    def from_dict(cose_key: Dict[int, Any]) -> COSEKeyInterface:
        """
        Create a COSE key from a CBOR-like dictionary with numeric keys.

        Args:
            cose_key (Dict[int, Any]): A CBOR-like dictionary with numeric keys
                of a COSE key.
        Returns:
            COSEKeyInterface: A COSE key object.
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
        if cose_key[1] == 3:
            return RSAKey(cose_key)
        if cose_key[1] == 4:
            if 3 not in cose_key or (
                not isinstance(cose_key[3], int) and not isinstance(cose_key[3], str)
            ):
                raise ValueError("alg(3) should be int or str(tstr).")
            if cose_key[3] in [1, 2, 3]:
                return AESGCMKey(cose_key)
            if cose_key[3] in [4, 5, 6, 7]:
                return HMACKey(cose_key)
            if cose_key[3] in [10, 11, 12, 13, 30, 31, 32, 33]:
                return AESCCMKey(cose_key)
            if cose_key[3] == 24:
                return ChaCha20Key(cose_key)
            raise ValueError(f"Unsupported or unknown alg(3): {cose_key[3]}.")
        raise ValueError(f"Unsupported or unknown kty(1): {cose_key[1]}.")

    @classmethod
    def from_symmetric_key(
        cls,
        key: Union[bytes, str] = b"",
        alg: Union[int, str] = "HMAC 256/256",
        kid: Union[bytes, str] = b"",
        key_ops: Optional[Union[List[int], List[str]]] = None,
    ) -> COSEKeyInterface:
        """
        Create a COSE key from a symmetric key.

        Args:
            key (Union[bytes, str]): A key bytes or string.
            alg (Union[int, str]): An algorithm label(int) or name(str). Supported ``alg`` are listed
                in `Supported COSE Algorithms <https://python-cwt.readthedocs.io/en/stable/algorithms.html>`_.
            kid (Union[bytes, str]): A key identifier.
            key_ops (Union[List[int], List[str]]): A list of key operation values. Following values can be used:
                ``1("sign")``, ``2("verify")``, ``3("encrypt")``, ``4("decrypt")``, ``5("wrap key")``,
                ``6("unwrap key")``, ``7("derive key")``, ``8("derive bits")``,
                ``9("MAC create")``, ``10("MAC verify")``
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
        """
        if isinstance(key, str):
            key = key.encode("utf-8")
        alg_id = alg if isinstance(alg, int) else COSE_ALGORITHMS_SYMMETRIC.get(alg, 0)
        if alg_id == 0:
            raise ValueError(f"Unsupported or unknown alg(3): {alg}.")

        cose_key = {
            1: 4,  # kty: 'Symmetric'
            3: alg_id,  # alg: int
            -1: key,  # k: bstr
        }
        if isinstance(kid, str):
            kid = kid.encode("utf-8")
        if kid:
            cose_key[2] = kid

        key_ops_labels: List[int] = []
        if key_ops and isinstance(key_ops, list):
            try:
                for ops in key_ops:
                    if isinstance(ops, str):
                        key_ops_labels.append(COSE_KEY_OPERATION_VALUES[ops])
                    else:
                        key_ops_labels.append(ops)
            except Exception:
                raise ValueError("Unsupported or unknown key_ops.")
        cose_key[4] = key_ops_labels
        return cls.from_dict(cose_key)

    @classmethod
    def from_bytes(cls, key_data: bytes) -> COSEKeyInterface:
        """
        Create a COSE key from CBOR-formatted key data.

        Args:
            key_data (bytes): CBOR-formatted key data.
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        cose_key = cbor2.loads(key_data)
        return cls.from_dict(cose_key)

    @classmethod
    def from_jwk(cls, data: Union[str, bytes, Dict[str, Any]]) -> COSEKeyInterface:
        """
        Create a COSE key from JWK (JSON Web Key).

        Args:
            jwk (Union[str, bytes, Dict[str, Any]]): JWK-formatted key data.
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        cose_key: Dict[int, Any] = {}

        # kty
        jwk: Dict[str, Any]
        if not isinstance(data, dict):
            jwk = json.loads(data)
        else:
            jwk = data
        if "kty" not in jwk:
            raise ValueError("kty not found.")
        if jwk["kty"] not in JWK_TYPES:
            raise ValueError(f"Unknown kty: {jwk['kty']}.")
        cose_key[1] = JWK_TYPES[jwk["kty"]]

        # kid
        if "kid" in jwk:
            if not isinstance(jwk["kid"], str):
                raise ValueError("kid should be str.")
            cose_key[2] = jwk["kid"].encode("utf-8")

        # alg
        if "alg" in jwk:
            if not isinstance(jwk["alg"], str):
                raise ValueError("alg should be str.")
            if jwk["alg"] not in COSE_NAMED_ALGORITHMS_SUPPORTED:
                raise ValueError(f"Unsupported or unknown alg: {jwk['alg']}.")
            cose_key[3] = COSE_NAMED_ALGORITHMS_SUPPORTED[jwk["alg"]]

        # key operation dependent conversion
        is_public = False
        if cose_key[1] == 4:  # Symmetric
            if "k" not in jwk or not isinstance(jwk["k"], str):
                raise ValueError("k is not found or invalid format.")
            cose_key[-1] = base64url_decode(jwk["k"])

        elif cose_key[1] == 3:  # RSA
            for k, v in jwk.items():
                if k not in JWK_PARAMS_RSA:
                    continue
                cose_key[JWK_PARAMS_RSA[k]] = base64url_decode(v)
            if -3 not in cose_key:
                is_public = True

        else:  # OKP/EC2
            if "crv" not in jwk:
                raise ValueError("crv not found.")
            if jwk["crv"] not in JWK_ELLIPTIC_CURVES:
                raise ValueError(f"Unknown crv: {jwk['crv']}.")
            cose_key[-1] = JWK_ELLIPTIC_CURVES[jwk["crv"]]

            if cose_key[1] == 1:  # OKP
                for k, v in jwk.items():
                    if k not in JWK_PARAMS_OKP:
                        continue
                    cose_key[JWK_PARAMS_OKP[k]] = base64url_decode(v)

            else:  # EC2
                for k, v in jwk.items():
                    if k not in JWK_PARAMS_EC:
                        continue
                    cose_key[JWK_PARAMS_EC[k]] = base64url_decode(v)
            if -4 not in cose_key:
                is_public = True

        # use/key_ops
        use = 0
        if "use" in jwk:
            if jwk["use"] == "enc":
                use = 4 if is_public else 3  # 3: encrypt, 4: decrypt
            elif jwk["use"] == "sig":
                if cose_key[1] == 4:
                    use = 10  # 10: MAC verify
                else:
                    use = 2 if is_public else 1  # 1: sign, 2: verify
            else:
                raise ValueError(f"Unknown use: {jwk['use']}.")
        if "key_ops" in jwk:
            if not isinstance(jwk["key_ops"], list):
                raise ValueError("key_ops should be list.")
            cose_key[4] = []
            try:
                for ops in jwk["key_ops"]:
                    cose_key[4].append(JWK_OPERATIONS[ops])
            except KeyError as err:
                raise ValueError("Unsupported or unknown key_ops.") from err
            if use != 0 and use not in cose_key[4]:
                raise ValueError("use and key_ops are conflicted each other.")
        else:
            if use != 0:
                cose_key[4] = []
                cose_key[4].append(use)
        return cls.from_dict(cose_key)

    @classmethod
    def from_pem(
        cls,
        key_data: Union[str, bytes],
        alg: Union[int, str] = "",
        kid: Union[bytes, str] = b"",
        key_ops: Optional[Union[List[int], List[str]]] = None,
    ) -> COSEKeyInterface:
        """
        Create a COSE key from PEM-formatted key data.

        Args:
            key_data (bytes): A PEM-formatted key data.
            alg (Union[int, str]): An algorithm label(int) or name(str).
                Different from ::func::`cwt.COSEKey.from_symmetric_key`, it is only used when an algorithm
                cannot be specified by the PEM data, such as RSA family algorithms.
            kid (Union[bytes, str]): A key identifier.
            key_ops (Union[List[int], List[str]]): A list of key operation values. Following values can be used:
                ``1("sign")``, ``2("verify")``, ``3("encrypt")``, ``4("decrypt")``, ``5("wrap key")``,
                ``6("unwrap key")``, ``7("derive key")``, ``8("derive bits")``,
                ``9("MAC create")``, ``10("MAC verify")``
        Returns:
            COSEKeyInterface: A COSE key object.
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

        key_ops_labels: List[int] = []
        if key_ops and isinstance(key_ops, list):
            try:
                for ops in key_ops:
                    if isinstance(ops, str):
                        key_ops_labels.append(COSE_KEY_OPERATION_VALUES[ops])
                    else:
                        key_ops_labels.append(ops)
            except Exception:
                raise ValueError("Unsupported or unknown key_ops.")
        cose_key[4] = key_ops_labels

        if isinstance(k, RSAPublicKey) or isinstance(k, RSAPrivateKey):
            if not alg:
                raise ValueError("alg parameter should be specified for an RSA key.")
            if isinstance(alg, str):
                if alg not in COSE_ALGORITHMS_RSA:
                    raise ValueError(f"Unsupported or unknow alg: {alg}.")
                alg = COSE_ALGORITHMS_RSA[alg]
            cose_key[1] = COSE_KEY_TYPES["RSA"]
            cose_key[3] = alg
            if isinstance(k, RSAPublicKey):
                pub_nums = k.public_numbers()
                cose_key[-1] = uint_to_bytes(pub_nums.n)
                cose_key[-2] = uint_to_bytes(pub_nums.e)
            else:
                priv_nums = k.private_numbers()
                cose_key[-1] = uint_to_bytes(priv_nums.public_numbers.n)
                cose_key[-2] = uint_to_bytes(priv_nums.public_numbers.e)
                cose_key[-3] = uint_to_bytes(priv_nums.d)
                cose_key[-4] = uint_to_bytes(priv_nums.p)
                cose_key[-5] = uint_to_bytes(priv_nums.q)
                cose_key[-6] = uint_to_bytes(priv_nums.dmp1)  # dP
                cose_key[-7] = uint_to_bytes(priv_nums.dmq1)  # dQ
                cose_key[-8] = uint_to_bytes(priv_nums.iqmp)  # qInv

        elif isinstance(k, EllipticCurvePrivateKey) or isinstance(
            k, EllipticCurvePublicKey
        ):
            key_len: int = 32
            cose_key[1] = COSE_KEY_TYPES["EC2"]
            if k.curve.name == "secp256r1":
                cose_key[-1] = 1
            elif k.curve.name == "secp384r1":
                cose_key[-1] = 2
                key_len = 48
            elif k.curve.name == "secp521r1":
                cose_key[-1] = 3
                key_len = 66
            elif k.curve.name == "secp256k1":
                cose_key[-1] = 8
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
            raise ValueError(f"Unsupported or unknown key: {type(k)}.")
        return cls.from_dict(cose_key)
