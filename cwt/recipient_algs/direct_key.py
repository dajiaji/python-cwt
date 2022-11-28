from typing import Any, Dict, List, Optional, Tuple, Union

from ..cose_key_interface import COSEKeyInterface
from .direct import Direct


class DirectKey(Direct):
    def __init__(self, protected: Dict[int, Any] = {}, unprotected: Dict[int, Any] = {}):
        super().__init__(protected, unprotected, b"", [])

        if self._alg != -6:
            raise ValueError("alg(1) should be direct(-6).")
        return

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        return self.to_list(), None

    def decode(
        self, key: COSEKeyInterface, aad: bytes = b"", alg: int = 0, as_cose_key: bool = False
    ) -> Union[bytes, COSEKeyInterface]:
        if not as_cose_key:
            return b""
        return key
