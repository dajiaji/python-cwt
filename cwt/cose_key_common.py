from typing import Any, Dict

from .cbor_processor import CBORProcessor
from .const import COSE_KEY_TYPES


class COSEKeyCommon(CBORProcessor):
    """
    The base class for COSE Key and Content Key Distribution Method.
    """

    def __init__(self, params: Dict[int, Any]):
        """
        Constructor.

        Args:
            params (Dict[int, Any]): A COSE key common parameters object formatted to a CBOR-like dictionary.
        """
        # Validate COSE Key common parameters.
        if 1 not in params:
            raise ValueError("kty(1) not found.")
        if not isinstance(params[1], int) and not isinstance(params[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if isinstance(params[1], int) and params[1] not in [1, 2, 3, 4, 5, 6]:
            raise ValueError(f"Unknown kty: {params[1]}")
        if isinstance(params[1], str) and params[1] not in COSE_KEY_TYPES:
            raise ValueError(f"Unknown kty: {params[1]}")
        self._kty: int = (
            params[1] if isinstance(params[1], int) else COSE_KEY_TYPES[params[1]]
        )
        if 2 in params and not isinstance(params[2], bytes):
            raise ValueError("kid(2) should be bytes(bstr).")
        if 3 in params and (
            not isinstance(params[3], int) and not isinstance(params[3], str)
        ):
            raise ValueError("alg(3) should be int or str(tstr).")
        if 4 in params and not isinstance(params[4], list):
            raise ValueError("key_ops(4) should be list.")
        if 5 in params and not isinstance(params[5], bytes):
            raise ValueError("Base IV(5) should be bytes(bstr).")
        self._object = params
        return

    @property
    def kty(self) -> int:
        """
        Identification of the key type.
        """
        return self._kty

    @property
    def kid(self) -> bytes:
        """
        A key identification value.
        """
        return self._object.get(2, None)

    @property
    def alg(self) -> int:
        """
        An algorithm that is used with the key.
        """
        return self._object.get(3, None)

    @property
    def key_ops(self) -> list:
        """
        Restrict set of permissible operations.
        """
        return self._object.get(4, None)

    @property
    def base_iv(self) -> bytes:
        """
        Base IV to be xor-ed with Partial IVs.
        """
        return self._object.get(5, None)

    def to_dict(self) -> Dict[int, Any]:
        """
        Returns a CBOR-like structure (Dict[int, Any]) of the COSE key.

        Returns:
            Dict[int, Any]: A CBOR-like structure of the COSE key.
        """
        return self._object
