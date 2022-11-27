from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from ..algs.ec2 import EC2Key
from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


class ECDH_AESKeyWrap(RecipientInterface):
    _ACCEPTABLE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["deriveKey"],
        COSE_KEY_OPERATION_VALUES["deriveBits"],
    ]

    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        sender_key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)
        self._sender_public_key: Any = None
        self._sender_key = sender_key
        self._recipient_key = recipient_key
        self._context = context

        self._apu = [
            self.unprotected[-21] if -21 in self.unprotected else None,
            self.unprotected[-22] if -22 in self.unprotected else None,
            self.unprotected[-23] if -23 in self.unprotected else None,
        ]
        self._apv = [
            self.unprotected[-24] if -24 in self.unprotected else None,
            self.unprotected[-25] if -25 in self.unprotected else None,
            self.unprotected[-26] if -26 in self.unprotected else None,
        ]

        if self._alg in [-29, -30, -31]:  # ECDH-ES
            if -1 in self.unprotected:
                self._unprotected[-1][3] = self._alg
                self._sender_public_key = COSEKey.new(self.unprotected[-1])
        elif self._alg in [-32, -33, -34]:  # ECDH-SS
            if -2 in self.unprotected:
                self._unprotected[-2][3] = self._alg
                self._sender_public_key = COSEKey.new(self.unprotected[-2])
        else:
            raise ValueError(f"Unknown alg(1) for ECDH with key wrap: {self._alg}.")

    def encode(
        self,
        plaintext: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> Tuple[List[Any], Optional[COSEKeyInterface]]:

        if not self._recipient_key:
            raise ValueError("recipient_key should be set in advance.")
        if not self._context:
            raise ValueError("context should be set in advance.")
        if self._alg in [-29, -30, -31]:
            # ECDH-ES
            self._sender_key = EC2Key({1: 2, -1: self._recipient_key.crv, 3: self._alg})
        else:
            # ECDH-SS (alg=-32, -33, -34)
            if not self._sender_key:
                raise ValueError("sender_key should be set in advance.")
        wrapping_key = self._sender_key.derive_key(self._context, public_key=self._recipient_key)
        if self._alg in [-29, -30, -31]:
            # ECDH-ES
            self._unprotected[-1] = self._to_cose_key(self._sender_key.key.public_key())
        else:
            # ECDH-SS (alg=-32, -33, -34)
            self._unprotected[-2] = self._to_cose_key(self._sender_key.key.public_key())
        try:
            self._ciphertext = aes_key_wrap(wrapping_key.key, plaintext)
        except Exception as err:
            raise EncodeError("Failed to wrap key.") from err
        return self.to_list(), None

    def decode(
        self,
        key: COSEKeyInterface,
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
        alg: int = 0,
        as_cose_key: bool = False,
    ) -> Union[bytes, COSEKeyInterface]:
        if not self._context:
            raise ValueError("context should be set.")
        if not self._sender_public_key:
            raise ValueError("sender_public_key should be set.")
        try:
            derived = key.derive_key(self._context, public_key=self._sender_public_key)
            derived_bytes = aes_key_unwrap(derived.key, self._ciphertext)
        except Exception as err:
            raise DecodeError("Failed to decode key.") from err
        if not as_cose_key:
            return derived_bytes
        if alg == 0:
            raise ValueError("alg should be set.")
        return COSEKey.from_symmetric_key(derived_bytes, alg=alg, kid=self._kid)
