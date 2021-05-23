from typing import Any, Dict, List

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
