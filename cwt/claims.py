from typing import Any, Dict, Union

from .cose_key import COSEKey


class Claims:

    def __init__(self, claims: Dict[int, Any]):
        self._claims = claims
        return

    @property
    def iss(self) -> str:
        return self._claims.get(1, None)

    @property
    def sub(self) -> str:
        return self._claims.get(2, None)

    @property
    def aud(self) -> str:
        return self._claims.get(3, None)

    @property
    def exp(self) -> int:
        return self._claims.get(4, None)

    @property
    def nbf(self) -> int:
        return self._claims.get(5, None)

    @property
    def iat(self) -> int:
        return self._claims.get(6, None)

    @property
    def cti(self) -> str:
        if 7 not in self._claims:
            return None
        return self._claims[7].decode("utf-8")

    @property
    def cnf(self) -> Union[COSEKey, bytes, str]:
        if 8 not in self._claims:
            return None
        return self._claims[8].decode("utf-8")

    def to_dict(self) -> Dict[int, Any]:
        return self._claims
