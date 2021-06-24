from typing import Any, Dict, List, Optional, Union

from .cose_key_interface import COSEKeyInterface
from .recipient import Recipient
from .recipient_interface import RecipientInterface


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
            res.append(Recipient.from_list(r))
        return cls(res)

    def extract(
        self,
        keys: List[COSEKeyInterface],
        context: Optional[Union[Dict[str, Any], List[Any]]] = None,
        alg: int = 0,
    ) -> COSEKeyInterface:
        """
        Decodes an appropriate key from recipients or keys privided as a parameter ``keys``.
        """
        for r in self._recipients:
            for k in keys:
                if k.kid != r.kid:
                    continue
                return r.extract(k, alg=alg, context=context)
        raise ValueError("Failed to derive a key.")
