from typing import Any

from ..recipient_interface import RecipientInterface


class Direct(RecipientInterface):
    def __init__(
        self,
        protected: dict[str | int, Any],
        unprotected: dict[str | int, Any],
        ciphertext: bytes = b"",
        recipients: list[Any] = [],
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)

        if self._alg == 0:
            raise ValueError("alg(1) not found.")
        return
