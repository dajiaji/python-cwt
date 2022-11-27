from typing import Any, Dict, List, Optional, Tuple, Union

from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError
from ..recipient_interface import RecipientInterface


class AESKeyWrap(RecipientInterface):
    _ACCEPTABLE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["wrapKey"],
        COSE_KEY_OPERATION_VALUES["unwrapKey"],
    ]

    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        sender_key: Optional[COSEKeyInterface] = None,
    ):
        if sender_key is None:
            raise ValueError("sender_key should be set.")
        if sender_key.alg not in [-3, -4, -5]:
            raise ValueError(f"Invalid alg in sender_key: {sender_key.alg}.")
        if 1 in protected and protected[1] != sender_key.alg:
            raise ValueError("algs in protected and sender_key do not match.")
        super().__init__(
            protected,
            unprotected,
            ciphertext,
            recipients,
            sender_key.key_ops,
            sender_key.key,
        )
        self._sender_key: COSEKeyInterface = sender_key

    def encode(
        self,
        plaintext: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> Tuple[List[Any], Optional[COSEKeyInterface]]:

        self._ciphertext = self._sender_key.wrap_key(plaintext)
        return self.to_list(), None

    def decode(
        self,
        key: COSEKeyInterface,
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        try:
            unwrapped = key.unwrap_key(self._ciphertext)
        except Exception as err:
            raise DecodeError("Failed to decode key.") from err
        if not as_cose_key:
            return unwrapped
        if not alg:
            raise ValueError("alg should be set.")
        return COSEKey.from_symmetric_key(unwrapped, alg=alg, kid=self._kid)
