from typing import Any, Dict, List, Optional, Tuple, Union

from ..cose_key_interface import COSEKeyInterface
from .direct import Direct


class DirectKey(Direct):
    def __init__(self, unprotected: Dict[int, Any]):
        super().__init__({}, unprotected, b"", [])

        if self._alg != -6:
            raise ValueError("alg(1) should be direct(-6).")
        return

    def encode(
        self,
        plaintext: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> Tuple[List[Any], Optional[COSEKeyInterface]]:
        return self.to_list(), None

    def decode(
        self,
        key: COSEKeyInterface,
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        if not as_cose_key:
            return b""
        return key

    def extract(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
    ) -> COSEKeyInterface:
        return key

    def decrypt(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
        payload: bytes = b"",
        nonce: bytes = b"",
        aad: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> bytes:
        return self.extract(key, alg).decrypt(payload, nonce, aad)
