from typing import Any, List, Optional

import cbor2

from .const import COSE_ALGORITHMS_KEY_WRAP
from .cose_key_interface import COSEKeyInterface
from .recipient import Recipient
from .recipient_interface import RecipientInterface
from .utils import base64url_decode, to_cis


class Recipients:
    """
    A Set of COSE Recipients.
    """

    def __init__(self, recipients: List[RecipientInterface]):
        self._recipients = recipients
        return

    @classmethod
    def from_list(cls, recipients: List[Any]):
        """
        Create Recipients from a CBOR-like list.
        """
        res: List[RecipientInterface] = []
        for r in recipients:
            res.append(cls._create_recipient(r))
        return cls(res)

    @classmethod
    def _create_recipient(cls, recipient: List[Any]) -> RecipientInterface:
        if not isinstance(recipient, list) or (
            len(recipient) != 3 and len(recipient) != 4
        ):
            raise ValueError("Invalid recipient format.")
        if not isinstance(recipient[0], bytes):
            raise ValueError("protected header should be bytes.")
        protected = {} if not recipient[0] else cbor2.loads(recipient[0])
        if not isinstance(recipient[1], dict):
            raise ValueError("unprotected header should be dict.")
        if not isinstance(recipient[2], bytes):
            raise ValueError("ciphertext should be bytes.")
        if len(recipient) == 3:
            return Recipient.from_dict(protected, recipient[1], recipient[2])
        if not isinstance(recipient[3], list):
            raise ValueError("recipients should be list.")
        recipients: List[RecipientInterface] = []
        for r in recipient[3]:
            recipients.append(cls._create_recipient(r))
        return Recipient.from_dict(protected, recipient[1], recipient[2], recipients)

    def derive_key(
        self,
        keys: Optional[List[COSEKeyInterface]] = None,
        materials: Optional[List[dict]] = None,
        alg_hint: int = 0,
    ) -> COSEKeyInterface:
        """
        Derive an appropriate key from recipients, keys privided as a parameter ``keys``
        or key materials as a parameter ``materials``.
        """
        if keys is not None:
            return self._derive_key_from_cose_keys(keys, alg_hint)
        if not materials:
            raise ValueError("Either keys or materials should be specified.")
        return self._derive_key_from_key_materials(materials, alg_hint)

    def _derive_key_from_cose_keys(
        self, keys: List[COSEKeyInterface], alg: int
    ) -> COSEKeyInterface:
        for r in self._recipients:
            for k in keys:
                if k.kid != r.kid:
                    continue
                if r.alg == -6:  # direct
                    return k
                elif r.alg in COSE_ALGORITHMS_KEY_WRAP.values():
                    r.set_key(k.key)
                    return r.unwrap_key(alg)
        raise ValueError("Failed to derive a key.")

    def _derive_key_from_key_materials(
        self, materials: List[dict], alg: int
    ) -> COSEKeyInterface:
        for r in self._recipients:
            recipient_alg = r.alg if isinstance(r.alg, int) else 0
            for m in materials:
                if m["kid"].encode("utf-8") != r.kid:
                    continue
                ctx = to_cis(m["context"], alg, recipient_alg)
                return r.derive_key(base64url_decode(m["value"]), context=ctx)
        raise ValueError("Failed to derive a key.")
