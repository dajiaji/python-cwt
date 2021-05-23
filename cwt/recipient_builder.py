import json
from typing import Any, Dict, Optional, Union

from .cbor_processor import CBORProcessor
from .const import COSE_ALGORITHMS_CKDM
from .recipient import Recipient
from .recipient_algs.direct import DirectKey


class RecipientBuilder(CBORProcessor):
    """
    A :class:`Recipient <cwt.Recipient>` Builder.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Constructor.

        At the current implementation, any ``options`` will be ignored.
        """
        self._options = options
        return

    def from_dict(
        self,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
    ) -> Recipient:
        """
        Create a recipient from a CBOR-like dictionary with numeric keys.

        Args:
            protected (Optional[Union[Dict[int, Any], bytes]]): Parameters that are to be
                cryptographically protected.
            unprotected (Optional[Dict[int, Any]]): Parameters that are not cryptographically
                protected.
        Returns:
            Recipient: A recipient object.
        Raises:
            ValueError: Invalid arguments.
        """
        alg = unprotected[1] if 1 in unprotected else protected.get(1, 0)
        if alg == 0:
            raise ValueError("alg should be specified.")
        if alg == -6:
            return DirectKey(unprotected)
        # if alg in [-10, -11]:
        #     return DirectHKDF(protected, unprotected)
        raise ValueError(f"Unsupported or unknown alg(1): {alg}.")

    def from_json(self, data: Union[str, bytes, Dict[str, Any]]) -> Recipient:
        """
        Create a recipient from JSON-formatted recipient data.

        Args:
            data (Union[str, bytes, Dict[str, Any]]): JSON-formatted recipient data.
        Returns:
            Recipient: A recipient object.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the key data.
        """
        protected: Dict[int, Any] = {}
        unprotected: Dict[int, Any] = {}
        recipient: Dict[str, Any]
        if not isinstance(data, dict):
            recipient = json.loads(data)
        else:
            recipient = data

        # alg
        if "alg" in recipient:
            if not isinstance(recipient["alg"], str):
                raise ValueError("alg should be str.")
            if recipient["alg"] not in COSE_ALGORITHMS_CKDM:
                raise ValueError(f"Unsupported or unknown alg: {recipient['alg']}.")
            if recipient["alg"] == "direct":
                unprotected[1] = COSE_ALGORITHMS_CKDM[recipient["alg"]]
            else:
                protected[1] = COSE_ALGORITHMS_CKDM[recipient["alg"]]

        # kid
        if "kid" in recipient:
            if not isinstance(recipient["kid"], str):
                raise ValueError("kid should be str.")
            unprotected[4] = recipient["kid"].encode("utf-8")

        return self.from_dict(protected, unprotected)


# export
recipient_builder = RecipientBuilder()
