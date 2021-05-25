from typing import Any, Dict, List, Optional

from .cbor_processor import CBORProcessor
from .recipient import Recipient
from .recipient_builder import RecipientBuilder
from .recipients import Recipients


class RecipientsBuilder(CBORProcessor):
    """
    A Recipients Builder.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self._options = options
        self._builder = RecipientBuilder()
        return

    def from_list(self, recipients: List[Any]) -> Recipients:
        """
        Create Recipient from a CBOR-like list.
        """
        res: List[Recipient] = []
        for r in recipients:
            res.append(self._create_recipient(r))
        return Recipients(res)

    def _create_recipient(self, recipient: List[Any]) -> Recipient:
        if not isinstance(recipient, list) or (
            len(recipient) != 3 and len(recipient) != 4
        ):
            raise ValueError("Invalid recipient format.")
        if not isinstance(recipient[0], bytes):
            raise ValueError("protected header should be bytes.")
        protected = {} if not recipient[0] else self._loads(recipient[0])
        if not isinstance(recipient[1], dict):
            raise ValueError("unprotected header should be dict.")
        if not isinstance(recipient[2], bytes):
            raise ValueError("ciphertext should be bytes.")
        if len(recipient) == 3:
            return self._builder.from_dict(protected, recipient[1], recipient[2])
        if not isinstance(recipient[3], list):
            raise ValueError("recipients should be list.")
        recipients: List[Recipient] = []
        for r in recipient[3]:
            recipients.append(self._create_recipient(r))
        return self._builder.from_dict(
            protected, recipient[1], recipient[2], recipients
        )
