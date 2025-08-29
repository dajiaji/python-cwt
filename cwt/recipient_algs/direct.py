from typing import Any, Dict, List, Union

from ..recipient_interface import RecipientInterface


class Direct(RecipientInterface):
    def __init__(
        self,
        protected: Dict[Union[str, int], Any],
        unprotected: Dict[Union[str, int], Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)

        if self._alg == 0:
            raise ValueError("alg(1) not found.")
        return
