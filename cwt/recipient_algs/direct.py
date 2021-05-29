from typing import Any, Dict, List

from ..recipient_interface import RecipientInterface


class Direct(RecipientInterface):
    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)

        if self._alg == 0:
            raise ValueError("alg(1) not found.")
        return
