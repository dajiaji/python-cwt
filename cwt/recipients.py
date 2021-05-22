from typing import List

from .cose_key import COSEKey
from .recipient import Recipient


class Recipients:
    """
    A Set of COSE Recipients.
    """

    def __init__(self, recipients: List[Recipient]):
        self._recipients = recipients
        return

    def derive_key(self, keys: List[COSEKey]) -> COSEKey:
        """
        Derive an appropriate key from recipients or keys privided as a parameter ``keys``.
        """
        for recipient in self._recipients:
            if recipient.alg == -6:
                for k in keys:
                    if k.kid == recipient.kid:
                        return k
        raise ValueError("Failed to derive a key.")
