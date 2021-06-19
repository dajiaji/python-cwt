from typing import Any, Dict, List, Optional, Union

from ..cose_key_interface import COSEKeyInterface
from .direct import Direct


class DirectKey(Direct):
    def __init__(
        self,
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):
        super().__init__({}, unprotected, ciphertext, recipients)

        if self._alg != -6:
            raise ValueError("alg(1) should be direct(-6).")
        return

    def decode_key(
        self,
        key: Union[COSEKeyInterface, bytes],
        alg: Optional[int] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:
        k: COSEKeyInterface
        if isinstance(key, bytes):
            raise ValueError("key should have COSEKeyInterface.")
        k = key
        return k
