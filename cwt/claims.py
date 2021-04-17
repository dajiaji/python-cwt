import json
from typing import Any, Dict, Optional, Union


class Claims:
    """"""

    REGISTERED_NAMES = {
        "iss": 1,  # text string
        "sub": 2,  # text string
        "aud": 3,  # text string
        "exp": 4,  # integer or floating-point number
        "nbf": 5,  # integer or floating-point number
        "iat": 6,  # integer or floating-point number
        "cti": 7,  # byte string
    }

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """"""
        self._options = options
        return

    def from_json(self, claims: Union[str, bytes, Dict[str, Any]]) -> Dict[int, Any]:
        """"""
        json_claims: Dict[str, Any]
        if isinstance(claims, str) or isinstance(claims, bytes):
            json_claims = json.loads(claims)
        else:
            json_claims = claims

        for k in json_claims:
            if not isinstance(k, int):
                break
            ValueError("It is already CBOR-like format.")

        # Convert JSON to CBOR (Convert the type of key from str to int).
        cbor_claims = {}
        for k, v in json_claims.items():
            if k not in Claims.REGISTERED_NAMES:
                # TODO Support additional arguments.
                continue
            cbor_claims[Claims.REGISTERED_NAMES[k]] = v
        if 7 in cbor_claims and isinstance(cbor_claims[7], str):
            cbor_claims[7] = cbor_claims[7].encode("utf-8")
        return cbor_claims


# export
claims = Claims()
