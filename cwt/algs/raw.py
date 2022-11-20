from typing import Any, Dict

from ..cose_key_interface import COSEKeyInterface


class RawKey(COSEKeyInterface):
    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)

        self._key: bytes = b""
        self._alg = None

        # Validate kty.
        if params[1] != 4:
            raise ValueError("kty(1) should be Symmetric(4).")

        # Validate k.
        if -1 not in params:
            raise ValueError("k(-1) should be set.")
        if not isinstance(params[-1], bytes):
            raise ValueError("k(-1) should be bytes(bstr).")
        self._key = params[-1]

    @property
    def key(self) -> bytes:
        return self._key

    def to_bytes(self) -> bytes:
        return self._key

    def to_dict(self) -> Dict[int, Any]:
        res = super().to_dict()
        res[-1] = self._key
        return res
