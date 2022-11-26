from typing import Any, Dict, List, Optional, Tuple

from ..cose_key_interface import COSEKeyInterface
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
    ) -> bytes:
        return b""

    # def apply(
    #     self,
    #     key: Optional[COSEKeyInterface] = None,
    #     recipient_key: Optional[COSEKeyInterface] = None,
    #     salt: Optional[bytes] = None,
    #     context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    #     external_aad: bytes = b"",
    #     aad_context: str = "Enc_Recipient",
    # ) -> COSEKeyInterface:
    #     if not key:
    #         raise ValueError("key should be set.")
    #     if key.kid:
    #         self._unprotected[4] = key.kid
    #     return key

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
