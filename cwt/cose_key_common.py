from typing import Any, Dict, Union

from .cbor_processor import CBORProcessor
from .const import COSE_NAMED_ALGORITHMS_SUPPORTED


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
        # kid
        if 2 in params and not isinstance(params[2], bytes):
            raise ValueError("kid(2) should be bytes(bstr).")
        self._kid = params[2] if 2 in params else None

        # alg
        self._alg = None
        if 3 in params:
            if not isinstance(params[3], int) and not isinstance(params[3], str):
                raise ValueError("alg(3) should be int or str(tstr).")
            if (
                isinstance(params[3], str)
                and params[3] not in COSE_NAMED_ALGORITHMS_SUPPORTED
            ):
                raise ValueError(f"Unsupported or unknown alg(3): {params[3]}.")
            self._alg = (
                params[3]
                if isinstance(params[3], int)
                else COSE_NAMED_ALGORITHMS_SUPPORTED[params[3]]
            )

        # Base IV
        if 5 in params and not isinstance(params[5], bytes):
            raise ValueError("Base IV(5) should be bytes(bstr).")
        self._base_iv = params[5] if 5 in params else None
        return

    @property
    def kid(self) -> Union[bytes, None]:
        """
        A key identification value.
        """
        return self._kid

    @property
    def alg(self) -> Union[int, None]:
        """
        An algorithm that is used with the key.
        """
        return self._alg

    @property
    def base_iv(self) -> Union[bytes, None]:
        """
        Base IV to be xor-ed with Partial IVs.
        """
        return self._base_iv
