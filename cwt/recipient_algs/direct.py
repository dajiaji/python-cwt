from typing import Any, Dict, Union

from ..recipient import Recipient


class Direct(Recipient):
    def __init__(
        self,
        protected: Union[bytes, Dict[int, Any]],
        unprotected: Dict[int, Any],
    ):
        super().__init__(protected, unprotected)

        if self._object[3] == 0:
            raise ValueError("alg(1) not found.")
        return


class DirectKey(Direct):
    def __init__(self, unprotected: Dict[int, Any]):
        super().__init__(b"", unprotected)

        if self._object[3] != -6:
            raise ValueError("alg(1) should be direct(-6).")
        return
