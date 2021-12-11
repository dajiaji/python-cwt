from typing import Any, Dict, List

from cbor2 import dumps, loads

from .const import COSE_ALGORITHMS_SYMMETRIC
from .exceptions import DecodeError, EncodeError


class CBORProcessor:
    def _dumps(self, obj: Any) -> bytes:
        try:
            return dumps(obj)
        except Exception as err:
            raise EncodeError("Failed to encode.") from err

    def _loads(self, s: bytes) -> Dict[int, Any]:
        try:
            return loads(s)
        except Exception as err:
            raise DecodeError("Failed to decode.") from err

    def _validate_context(self, context: List[Any]):
        if len(context) != 4 and len(context) != 5:
            raise ValueError("Invalid context information.")
        # AlgorithmID
        if not isinstance(context[0], int):
            raise ValueError("AlgorithmID should be int.")
        if context[0] not in COSE_ALGORITHMS_SYMMETRIC.values():
            raise ValueError(f"Unsupported or unknown algorithm: {context[0]}.")
        # PartyVInfo
        if not isinstance(context[1], list) or len(context[1]) != 3:
            raise ValueError("PartyUInfo should be list(size=3).")
        # PartyUInfo
        if not isinstance(context[2], list) or len(context[2]) != 3:
            raise ValueError("PartyVInfo should be list(size=3).")
        # SuppPubInfo
        if not isinstance(context[3], list) or (len(context[3]) != 2 and len(context[3]) != 3):
            raise ValueError("SuppPubInfo should be list(size=2 or 3).")
