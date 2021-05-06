from typing import Any, Dict, List, Union

from .const import CWT_CLAIM_NAMES


class Claims:
    """
    A class for handling CWT Claims like JWT claims.
    """

    def __init__(
        self,
        claims: Dict[int, Any],
        claim_names: Dict[str, int] = CWT_CLAIM_NAMES,
    ):
        if -260 in claims and not isinstance(claims[-260], dict):
            raise ValueError("hcert(-260) should be map.")
        if -259 in claims and not isinstance(claims[-259], bytes):
            raise ValueError("EUPHNonce(-259) should be bstr.")
        if -258 in claims and not isinstance(claims[-258], bytes):
            raise ValueError("EATMAROEPrefix(-258) should be bstr.")
        if -257 in claims and not isinstance(claims[-257], list):
            raise ValueError("EAT-FDO(-257) should be array.")
        if 1 in claims and not isinstance(claims[1], str):
            raise ValueError("iss(1) should be str.")
        if 2 in claims and not isinstance(claims[2], str):
            raise ValueError("sub(2) should be str.")
        if 3 in claims:
            if not isinstance(claims[3], str) and not isinstance(claims[3], list):
                raise ValueError("aud(3) should be str or list[str].")
            if isinstance(claims[3], list):
                for c in claims[3]:
                    if not isinstance(c, str):
                        raise ValueError("aud(3) should be str or list[str].")
        if 4 in claims and not (
            isinstance(claims[4], int) or isinstance(claims[4], float)
        ):
            raise ValueError("exp(4) should be int or float.")
        if 5 in claims and not (
            isinstance(claims[5], int) or isinstance(claims[5], float)
        ):
            raise ValueError("nbf(5) should be int or float.")
        if 6 in claims and not (
            isinstance(claims[6], int) or isinstance(claims[6], float)
        ):
            raise ValueError("iat(6) should be int or float.")
        if 7 in claims and not isinstance(claims[7], bytes):
            raise ValueError("cti(7) should be bytes.")
        if 8 in claims:
            if not isinstance(claims[8], dict):
                raise ValueError("cnf(8) should be dict.")
            if 1 in claims[8]:
                if not isinstance(claims[8][1], dict):
                    raise ValueError("COSE_Key in cnf(8) should be dict.")
            elif 2 in claims[8]:
                if not isinstance(claims[8][2], list):
                    raise ValueError("Encrypted_COSE_Key in cnf(8) should be list.")
            elif 3 in claims[8]:
                if not isinstance(claims[8][3], bytes):
                    raise ValueError("kid in cnf(8) should be bytes.")
            else:
                raise ValueError(
                    "cnf(8) should include COSE_Key, Encrypted_COSE_Key, or kid."
                )
        self._claims = claims
        self._claim_names = claim_names
        return

    @property
    def iss(self) -> Union[str, None]:
        return self._claims.get(1, None)

    @property
    def sub(self) -> Union[str, None]:
        return self._claims.get(2, None)

    @property
    def aud(self) -> Union[str, None]:
        return self._claims.get(3, None)

    @property
    def exp(self) -> Union[int, None]:
        return self._claims.get(4, None)

    @property
    def nbf(self) -> Union[int, None]:
        return self._claims.get(5, None)

    @property
    def iat(self) -> Union[int, None]:
        return self._claims.get(6, None)

    @property
    def cti(self) -> Union[str, None]:
        if 7 not in self._claims:
            return None
        return self._claims[7].decode("utf-8")

    @property
    def cnf(self) -> Union[Dict[int, Any], List[Any], str, None]:
        if 8 not in self._claims:
            return None
        if 1 in self._claims[8]:
            key: Dict[int, Any] = self._claims[8][1]
            return key
        if 2 in self._claims[8]:
            eck: List[Any] = self._claims[8][2]
            return eck
        kid: bytes = self._claims[8][3]
        return kid.decode("utf-8")

    def get(self, key: Union[str, int]) -> Any:
        """
        Gets a claim value with a claim key.

        Args:
            key (Union[str, int]): A claim key.
        Returns:
            Any: The value of the claim.
        """
        int_key = 0
        if isinstance(key, str):
            int_key = self._claim_names.get(key, 0)
        else:
            int_key = key
        return self._claims.get(int_key, None) if int_key != 0 else None

    def to_dict(self) -> Dict[int, Any]:
        return self._claims
