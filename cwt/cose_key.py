from typing import Any, Dict, List, Optional, Union

import cbor2
from cryptography import x509
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
from .algs.raw import RawKey
from .algs.rsa import RSAKey
from .algs.symmetric import (
    AESCBCKey,
    AESCCMKey,
    AESCTRKey,
    AESGCMKey,
    AESKeyWrap,
    ChaCha20Key,
    HMACKey,
)
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
from .enums import COSEKeyParams
from .utils import jwk_to_cose_key_params, uint_to_bytes


class COSEKey:
    """
    A :class:`COSEKeyInterface <cwt.COSEKeyInterface>` Builder.
    """

    @staticmethod
    def new(params: Dict[int, Any]) -> COSEKeyInterface:
        """
        Creates a COSE_Key object from a COSE_Key structure, which is a dictionary with numeric keys.

        Args:
            params (Dict[int, Any]): A dictionary with numeric keys of a COSE key.
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
        """

        # Validate COSE Key common parameters.
        if COSEKeyParams.KTY not in params:
            raise ValueError("kty(1) not found.")
        if not isinstance(params[COSEKeyParams.KTY], int) and not isinstance(params[COSEKeyParams.KTY], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if params[COSEKeyParams.KTY] == 1:
            return OKPKey(params)
        if params[COSEKeyParams.KTY] == 2:
            return EC2Key(params)
        if params[COSEKeyParams.KTY] == 3:
            return RSAKey(params)
        if params[COSEKeyParams.KTY] != 4:
            raise ValueError(f"Unsupported or unknown kty(1): {params[1]}.")
        if COSEKeyParams.ALG not in params:
            raise ValueError("alg(3) not found.")
        if not isinstance(params[COSEKeyParams.ALG], int) and not isinstance(params[COSEKeyParams.ALG], str):
            raise ValueError("alg(3) should be int or str(tstr).")
        if params[COSEKeyParams.ALG] in [1, 2, 3]:
            return AESGCMKey(params)
        if params[COSEKeyParams.ALG] in [4, 5, 6, 7]:
            return HMACKey(params)
        if params[COSEKeyParams.ALG] in [10, 11, 12, 13, 30, 31, 32, 33]:
            return AESCCMKey(params)
        if params[COSEKeyParams.ALG] == 24:
            return ChaCha20Key(params)
        if params[COSEKeyParams.ALG] in [-3, -4, -5]:
            return AESKeyWrap(params)
        if params[COSEKeyParams.ALG] in [-65534, -65533, -65532]:
            return AESCTRKey(params)
        if params[COSEKeyParams.ALG] in [-65531, -65530, -65529]:
            return AESCBCKey(params)
        raise ValueError(f"Unsupported or unknown alg(3): {params[3]}.")

    @classmethod
    def generate_symmetric_key(
        cls,
        alg: Union[int, str] = "",
        kid: Union[bytes, str] = b"",
        key_ops: Optional[Union[List[int], List[str]]] = None,
    ) -> COSEKeyInterface:
        """
        Generates a symmetric COSE key from from a randomly genarated byte string.

        Args:
            alg (Union[int, str]): An algorithm label(int) or name(str).
                Supported ``alg`` are listed in
                `Supported COSE Algorithms <https://python-cwt.readthedocs.io/en/stable/algorithms.html>`_.
            kid (Union[bytes, str]): A key identifier.
            key_ops (Union[List[int], List[str]]): A list of key operation values.
                Following values can be used:
                ``1("sign")``, ``2("verify")``, ``3("encrypt")``, ``4("decrypt")``, ``5("wrap key")``,
                ``6("unwrap key")``, ``7("derive key")``, ``8("derive bits")``,
                ``9("MAC create")``, ``10("MAC verify")``
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
        """
        return cls.from_symmetric_key(b"", alg, kid, key_ops)

    @classmethod
    def from_symmetric_key(
        cls,
        key: Union[bytes, str] = b"",
        alg: Union[int, str] = "",
        kid: Union[bytes, str] = b"",
        key_ops: Optional[Union[List[int], List[str]]] = None,
    ) -> COSEKeyInterface:
        """
        Creates a COSE key from a symmetric key.

        Args:
            key (Union[bytes, str]): A key bytes or string.
            alg (Union[int, str]): An algorithm label(int) or name(str).
                Supported ``alg`` are listed in
                `Supported COSE Algorithms <https://python-cwt.readthedocs.io/en/stable/algorithms.html>`_.
            kid (Union[bytes, str]): A key identifier.
            key_ops (Union[List[int], List[str]]): A list of key operation values.
                Following values can be used:
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
        if alg == "":
            return RawKey({1: 4, -1: key})
        alg_id = alg if isinstance(alg, int) else COSE_ALGORITHMS_SYMMETRIC.get(alg, 0)
        if alg_id == 0:
            raise ValueError(f"Unsupported or unknown alg(3): {alg}.")

        params: Dict[int, Any] = {
            COSEKeyParams.KTY: 4,  # kty: 'Symmetric'
            COSEKeyParams.ALG: alg_id,  # alg: int
            COSEKeyParams.K: key,  # k: bstr
        }
        if isinstance(kid, str):
            kid = kid.encode("utf-8")
        if kid:
            params[2] = kid

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
        params[4] = key_ops_labels
        return cls.new(params)

    @classmethod
    def from_bytes(cls, key_data: bytes) -> COSEKeyInterface:
        """
        Creates a COSE key from CBOR-formatted key data.

        Args:
            key_data (bytes): CBOR-formatted key data.
        Returns:
            COSEKeyInterface: A COSE key object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        params = cbor2.loads(key_data)
        return cls.new(params)

    @classmethod
    def from_jwk(cls, data: Union[str, bytes, Dict[str, Any]]) -> COSEKeyInterface:
        """
        Creates a COSE key from JWK (JSON Web Key).

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
        Creates a COSE key from PEM-formatted key data.

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
        elif "BEGIN CERTIFICATE" in key_str:
            k = x509.load_pem_x509_certificate(key_data).public_key()
        elif "BEGIN PRIVATE" in key_str:
            k = load_pem_private_key(key_data, password=None)
        elif "BEGIN EC PRIVATE" in key_str:
            k = load_pem_private_key(key_data, password=None)
        else:
            raise ValueError("Failed to decode PEM.")

        params: Dict[int, Any] = {}
        if isinstance(kid, str):
            kid = kid.encode("utf-8")
        if kid:
            params[2] = kid

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
        params[4] = key_ops_labels

        if isinstance(k, RSAPublicKey) or isinstance(k, RSAPrivateKey):
            if not alg:
                raise ValueError("alg parameter should be specified for an RSA key.")
            if isinstance(alg, str):
                if alg not in COSE_ALGORITHMS_RSA:
                    raise ValueError(f"Unsupported or unknown alg: {alg}.")
                alg = COSE_ALGORITHMS_RSA[alg]
            params[1] = COSE_KEY_TYPES["RSA"]
            params[3] = alg
            if isinstance(k, RSAPublicKey):
                pub_nums = k.public_numbers()
                params[-1] = uint_to_bytes(pub_nums.n)
                params[-2] = uint_to_bytes(pub_nums.e)
            else:
                priv_nums = k.private_numbers()
                params[-1] = uint_to_bytes(priv_nums.public_numbers.n)
                params[-2] = uint_to_bytes(priv_nums.public_numbers.e)
                params[-3] = uint_to_bytes(priv_nums.d)
                params[-4] = uint_to_bytes(priv_nums.p)
                params[-5] = uint_to_bytes(priv_nums.q)
                params[-6] = uint_to_bytes(priv_nums.dmp1)  # dP
                params[-7] = uint_to_bytes(priv_nums.dmq1)  # dQ
                params[-8] = uint_to_bytes(priv_nums.iqmp)  # qInv

        elif isinstance(k, EllipticCurvePrivateKey) or isinstance(k, EllipticCurvePublicKey):
            if alg:
                if isinstance(alg, str):
                    if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT:
                        alg = COSE_ALGORITHMS_CKDM_KEY_AGREEMENT[alg]
                    elif alg in COSE_ALGORITHMS_SIG_EC2:
                        alg = COSE_ALGORITHMS_SIG_EC2[alg]
                    else:
                        raise ValueError(f"Unsupported or unknown alg for EC2: {alg}.")
                params[3] = alg
            params.update(EC2Key.to_cose_key(k))
        else:
            if alg:
                if isinstance(alg, str):
                    if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT:
                        alg = COSE_ALGORITHMS_CKDM_KEY_AGREEMENT[alg]
                    elif alg in COSE_ALGORITHMS_SIG_OKP:
                        alg = COSE_ALGORITHMS_SIG_OKP[alg]
                    else:
                        raise ValueError(f"Unsupported or unknown alg for OKP: {alg}.")
                params[3] = alg
            params.update(OKPKey.to_cose_key(k))
        return cls.new(params)
