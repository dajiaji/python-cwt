from typing import Any, Dict, List, Optional, Union

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .algs.ec2 import EC2Key
from .algs.okp import OKPKey
from .algs.rsa import RSAKey
from .algs.symmetric import AESCCMKey, AESGCMKey, ChaCha20Key, HMACKey
from .const import (
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    COSE_ALGORITHMS_RSA,
    COSE_ALGORITHMS_SIG_EC2,
    COSE_ALGORITHMS_SIG_OKP,
    COSE_ALGORITHMS_SYMMETRIC,
    COSE_KEY_OPERATION_VALUES,
    COSE_KEY_TYPES,
)
from .cose_key_interface import COSEKeyInterface
from .utils import jwk_to_cose_key_params, uint_to_bytes


class COSEKey:
    """
    A :class:`COSEKeyInterface <cwt.COSEKeyInterface>` Builder.
    """

    @staticmethod
    def new(cose_key: Dict[int, Any]) -> COSEKeyInterface:
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
        return cls.new(cose_key)

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
        return cls.new(cose_key)

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
        return cls.new(jwk_to_cose_key_params(data))

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
                    raise ValueError(f"Unsupported or unknown alg: {alg}.")
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
            if alg:
                if isinstance(alg, str):
                    if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT:
                        alg = COSE_ALGORITHMS_CKDM_KEY_AGREEMENT[alg]
                    elif alg in COSE_ALGORITHMS_SIG_EC2:
                        alg = COSE_ALGORITHMS_SIG_EC2[alg]
                    else:
                        raise ValueError(f"Unsupported or unknown alg for EC2: {alg}.")
                cose_key[3] = alg
            cose_key.update(EC2Key.to_cose_key(k))
        else:
            if alg:
                if isinstance(alg, str):
                    if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT:
                        alg = COSE_ALGORITHMS_CKDM_KEY_AGREEMENT[alg]
                    elif alg in COSE_ALGORITHMS_SIG_OKP:
                        alg = COSE_ALGORITHMS_SIG_OKP[alg]
                    else:
                        raise ValueError(f"Unsupported or unknown alg for OKP: {alg}.")
                cose_key[3] = alg
            cose_key.update(OKPKey.to_cose_key(k))
        return cls.new(cose_key)
