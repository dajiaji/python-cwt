from typing import Any

from ..cose_key_interface import COSEKeyInterface
from .direct import Direct


class DirectKey(Direct):
    def __init__(self, protected: dict[str | int, Any] = {}, unprotected: dict[str | int, Any] = {}):
        super().__init__(protected, unprotected, b"", [])

        if self._alg != -6:
            raise ValueError("alg(1) should be direct(-6).")
        return

    def encode(self, plaintext: bytes = b"", aad: bytes = b"") -> tuple[list[Any], COSEKeyInterface | None]:
        return self.to_list(), None

    def decode(
        self, key: COSEKeyInterface, aad: bytes = b"", alg: int = 0, as_cose_key: bool = False
    ) -> bytes | COSEKeyInterface:
        if not as_cose_key:
            return b""
        return key
