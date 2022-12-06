from typing import Any, Dict, List, Optional, Union

import cbor2

from .const import (  # COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP,
    COSE_ALGORITHMS_CKDM,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP,
    COSE_ALGORITHMS_HPKE,
    COSE_ALGORITHMS_KEY_WRAP,
    COSE_ALGORITHMS_RECIPIENT,
)
from .cose_key import COSEKey
from .cose_key_interface import COSEKeyInterface
from .recipient_algs.aes_key_wrap import AESKeyWrap
from .recipient_algs.direct_hkdf import DirectHKDF
from .recipient_algs.direct_key import DirectKey
from .recipient_algs.ecdh_aes_key_wrap import ECDH_AESKeyWrap
from .recipient_algs.ecdh_direct_hkdf import ECDH_DirectHKDF
from .recipient_algs.hpke import HPKE
from .recipient_interface import RecipientInterface
from .utils import to_cose_header, to_recipient_context


class Recipient:
    """
    A :class:`RecipientInterface <cwt.RecipientInterface>` Builder.
    """

    @classmethod
    def new(
        cls,
        protected: dict = {},
        unprotected: dict = {},
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        sender_key: Optional[COSEKeyInterface] = None,
        recipient_key: Optional[COSEKeyInterface] = None,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> RecipientInterface:
        """
        Creates a recipient from a CBOR-like dictionary with numeric keys.

        Args:
            protected (dict): Parameters that are to be cryptographically protected.
            unprotected (dict): Parameters that are not cryptographically protected.
            ciphertext (List[Any]): A cipher text.
            sender_key (Optional[COSEKeyInterface]): A sender private key as COSEKey.
            recipient_key (Optional[COSEKeyInterface]): A recipient public key as COSEKey.
            context (Optional[Union[List[Any], Dict[str, Any]]]): Context
                information structure.
        Returns:
            RecipientInterface: A recipient object.
        Raises:
            ValueError: Invalid arguments.
        """
        p = to_cose_header(protected, algs=COSE_ALGORITHMS_RECIPIENT)
        u = to_cose_header(unprotected, algs=COSE_ALGORITHMS_RECIPIENT)

        if 1 in p and 1 in u:
            raise ValueError("alg appear both in protected and unprotected.")
        alg = u[1] if 1 in u else p.get(1, 0)
        if alg == 0:
            raise ValueError("alg should be specified.")

        if alg in COSE_ALGORITHMS_CKDM.values():  # Direct encryption mode.
            if len(recipients) > 0:
                raise ValueError("Recipients for direct encryption mode don't have recipients.")
            if len(ciphertext) > 0:
                raise ValueError(
                    "The ciphertext in the recipients for direct encryption mode must be a zero-length byte string."
                )

        if alg == -6:
            return DirectKey(p, u)
        if alg in COSE_ALGORITHMS_KEY_WRAP.values():
            if len(protected) > 0:
                raise ValueError("The protected header must be a zero-length string in key wrap mode with an AE algorithm.")
            if not sender_key:
                sender_key = COSEKey.from_symmetric_key(alg=alg)
            return AESKeyWrap(u, ciphertext, recipients, sender_key)
        if alg in COSE_ALGORITHMS_HPKE.values():
            return HPKE(p, u, ciphertext, recipients, recipient_key)  # TODO sender_key

        if context is None:
            raise ValueError("context should be set.")
        ctx = to_recipient_context(alg, u, context)

        if alg in [-10, -11]:
            return DirectHKDF(p, u, ctx)
        if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT.values():
            return ECDH_DirectHKDF(p, u, ciphertext, recipients, sender_key, recipient_key, ctx)
        if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP.values():
            return ECDH_AESKeyWrap(p, u, ciphertext, recipients, sender_key, recipient_key, ctx)
        raise ValueError(f"Unsupported or unknown alg(1): {alg}.")

    @classmethod
    def from_list(
        cls,
        recipient: List[Any],
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ) -> RecipientInterface:
        """
        Creates a recipient from a raw COSE array data.

        Args:
            data (Union[str, bytes, Dict[str, Any]]): JSON-formatted recipient data.
        Returns:
            RecipientInterface: A recipient object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        if not isinstance(recipient, list) or (len(recipient) != 3 and len(recipient) != 4):
            raise ValueError("Invalid recipient format.")
        if not isinstance(recipient[0], bytes):
            raise ValueError("protected header should be bytes.")
        protected = {} if not recipient[0] else cbor2.loads(recipient[0])
        if not isinstance(recipient[1], dict):
            raise ValueError("unprotected header should be dict.")
        if not isinstance(recipient[2], bytes):
            raise ValueError("ciphertext should be bytes.")
        if len(recipient) == 3:
            rec = cls.new(protected, recipient[1], recipient[2], context=context)
            rec._set_b_protected(recipient[0])
            return rec
        if not isinstance(recipient[3], list):
            raise ValueError("recipients should be list.")
        recipients: List[RecipientInterface] = []
        for r in recipient[3]:
            recipients.append(cls.from_list(r))
        rec = cls.new(protected, recipient[1], recipient[2], recipients, context=context)
        rec._set_b_protected(recipient[0])
        return rec
