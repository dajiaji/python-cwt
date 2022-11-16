from typing import Any, Dict, List, Optional, Union

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from ..cose_key_interface import COSEKeyInterface
from ..exceptions import DecodeError, EncodeError
from ..recipient_interface import RecipientInterface


class HPKE(RecipientInterface):
    def __init__(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):
        super().__init__(protected, unprotected, ciphertext, recipients)

        if self._alg != -1:
            raise ValueError("alg should be HPKE(-1).")
        if -4 not in unprotected:
            raise ValueError("HPKE sender information(-4) not found.")
        if 1 not in unprotected[-4]:
            raise ValueError("kem id(1) not found in HPKE sender information(-4).")
        if 2 not in unprotected[-4]:
            raise ValueError("kdf id(2) not found in HPKE sender information(-4).")
        if 3 not in unprotected[-4]:
            raise ValueError("aead id(3) not found in HPKE sender information(-4).")
        self._suite = CipherSuite.new(KEMId(unprotected[-4][1]), KDFId(unprotected[-4][2]), AEADId(unprotected[-4][3]))
        return

    def apply(
        self,
        key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        salt: Optional[bytes] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> COSEKeyInterface:
        if not recipient_key:
            raise ValueError("recipient_key should be set.")

        self._recipient_key = recipient_key
        self._kem_key = self._to_kem_key(recipient_key)
        return self._recipient_key

    def to_list(self, payload: bytes = b"", external_aad: bytes = b"", aad_context: str = "Enc_Recipient") -> List[Any]:
        enc_structure = [aad_context, self._dumps(self._protected), external_aad]
        aad = self._dumps(enc_structure)
        enc, sender = self._suite.create_sender_context(self._kem_key)
        self._unprotected[-4][4] = enc
        try:
            self._ciphertext = sender.seal(payload, aad=aad)
            return super().to_list(payload, external_aad, aad_context)
        except Exception as err:
            raise EncodeError("Failed to seal.") from err

    def decrypt(
        self,
        key: COSEKeyInterface,
        alg: Optional[int] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
        payload: bytes = b"",
        nonce: bytes = b"",
        aad: bytes = b"",
        external_aad: bytes = b"",
        aad_context: str = "Enc_Recipient",
    ) -> bytes:
        enc_structure = [aad_context, self._dumps(self._protected), external_aad]
        aad = self._dumps(enc_structure)
        recipient = self._suite.create_recipient_context(self._unprotected[-4][4], self._to_kem_key(key))
        try:
            return recipient.open(self._ciphertext, aad=aad)
        except Exception as err:
            raise DecodeError("Failed to open.") from err

    def _to_kem_key(self, src: COSEKeyInterface) -> KEMKeyInterface:
        return KEMKey.from_pyca_cryptography_key(src.key)
