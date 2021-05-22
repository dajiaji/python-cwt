from typing import Any, Dict, List, Optional, Union

from .cose_key import COSEKey
from .cose_key_common import COSEKeyCommon


class Recipient(COSEKeyCommon):
    """
    A COSE Recipient.
    """

    def __init__(
        self,
        protected: Optional[Union[bytes, Dict[int, Any]]] = None,
        unprotected: Optional[Dict[int, Any]] = None,
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
    ):

        protected = {} if protected is None else protected
        unprotected = {} if unprotected is None else unprotected

        params: Dict[int, Any] = {1: 4}  # Support only Symmetric key.

        # kid
        if 4 in unprotected:
            if not isinstance(unprotected[4], bytes):
                raise ValueError("unprotected[4](kid) should be bytes.")
            params[2] = unprotected[4]
        else:
            params[2] = b""

        # alg
        if 1 in protected:
            if not isinstance(protected[1], int):
                raise ValueError("protected[1](alg) should be int.")
            params[3] = protected[1]
        elif 1 in unprotected:
            if not isinstance(unprotected[1], int):
                raise ValueError("unprotected[1](alg) should be int.")
            params[3] = unprotected[1]
            if params[3] == -6:  # direct
                if len(protected) != 0:
                    raise ValueError("protected header should be empty.")
                if len(ciphertext) != 0:
                    raise ValueError("ciphertext should be zero-length bytes.")
                if len(recipients) != 0:
                    raise ValueError("recipients should be absent.")
        else:
            params[3] = 0

        # iv
        if 5 in unprotected:
            if not isinstance(unprotected[5], bytes):
                raise ValueError("unprotected[5](iv) should be bytes.")
            params[5] = unprotected[5]

        super().__init__(params)

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
