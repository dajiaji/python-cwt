from typing import Any, Dict, List, Optional, Union

from .cbor_processor import CBORProcessor
from .cose_key import COSEKey


class Recipient(CBORProcessor):
    """
    A COSE Recipient.
    """

    def __init__(
        self,
        protected: Union[bytes, Dict[int, Any]] = {},
        unprotected: Dict[int, Any] = {},
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):

        # Validate unprotected
        if 1 in unprotected:
            alg = unprotected[1]
            if alg == -6:  # direct
                if len(protected) != 0:
                    raise ValueError("protected header should be empty.")
                if len(ciphertext) != 0:
                    raise ValueError("ciphertext should be zero-length bytes.")
                if len(recipients) != 0:
                    raise ValueError("recipients should be absent.")
        if protected == b"":
            self._protected = {}
        elif isinstance(protected, bytes):
            self._protected = self._loads(protected)
        else:
            self._protected = protected
        self._unprotected = unprotected
        self._ciphertext = ciphertext

        # Validate recipients
        self._recipients: List[Recipient] = []
        if not recipients:
            return
        for recipient in recipients:
            if not isinstance(recipient, Recipient):
                raise ValueError("Invalid child recipient.")
            self._recipients.append(recipient)
        return

    @property
    def protected(self) -> Dict[int, Any]:
        return self._protected

    @property
    def unprotected(self) -> Dict[int, Any]:
        return self._unprotected

    @property
    def alg(self) -> int:
        return self._unprotected.get(1, 0)

    @property
    def kid(self) -> bytes:
        return self._unprotected.get(4, b"")

    @property
    def ciphertext(self) -> bytes:
        return self._ciphertext

    @property
    def recipients(self) -> Union[List[Any], None]:
        return self._recipients

    def to_list(self) -> List[Any]:
        b_protected = self._dumps(self._protected) if self._protected else b""
        b_ciphertext = self._ciphertext if self._ciphertext else b""
        res: List[Any] = [b_protected, self._unprotected, b_ciphertext]
        if not self._recipients:
            return res

        children = []
        for recipient in self._recipients:
            children.append(recipient.to_list())
        res.append(children)
        return res


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


class RecipientsBuilder:
    """
    A Recipients Builder.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self._options = options
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
        if not isinstance(recipient[1], dict):
            raise ValueError("unprotected header should be dict.")
        if not isinstance(recipient[2], bytes):
            raise ValueError("ciphertext should be bytes.")
        if len(recipient) == 3:
            return Recipient(recipient[0], recipient[1], recipient[2])
        if not isinstance(recipient[3], list):
            raise ValueError("recipients should be list.")
        recipients: List[Recipient] = []
        for r in recipient[3]:
            recipients.append(self._create_recipient(r))
        return Recipient(recipient[0], recipient[1], recipient[2], recipients)
