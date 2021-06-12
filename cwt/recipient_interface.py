from typing import Any, Dict, List, Optional, Union

from .cose_key_interface import COSEKeyInterface


class RecipientInterface(COSEKeyInterface):
    """
    The interface class for a COSE Recipient.
    """

    def __init__(
        self,
        protected: Optional[Dict[int, Any]] = None,
        unprotected: Optional[Dict[int, Any]] = None,
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        key_ops: List[int] = [],
        key: bytes = b"",
    ):

        """
        Constructor.

        Args:
            protected (Optional[Dict[int, Any]]): Parameters that are to be cryptographically
                protected.
            unprotected (Optional[Dict[int, Any]]): Parameters that are not cryptographically
                protected.
            ciphertext: A ciphertext encoded as bytes.
            recipients: A list of recipient information structures.
            key_ops: A list of operations that the key is to be used for.
            key: A body of the key as bytes.
        """
        protected = {} if protected is None else protected
        unprotected = {} if unprotected is None else unprotected

        params: Dict[int, Any] = {1: 4}  # Support only Symmetric key.

        # kid
        if 4 in unprotected:
            if not isinstance(unprotected[4], bytes):
                raise ValueError("unprotected[4](kid) should be bytes.")
            params[2] = unprotected[4]

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

        # key_ops
        if key_ops:
            params[4] = key_ops

        # iv
        if 5 in unprotected:
            if not isinstance(unprotected[5], bytes):
                raise ValueError("unprotected[5](iv) should be bytes.")
            params[5] = unprotected[5]

        super().__init__(params)

        self._protected = protected
        self._unprotected = unprotected
        self._ciphertext = ciphertext
        self._key = key

        # Validate recipients
        self._recipients: List[RecipientInterface] = []
        if not recipients:
            return
        for recipient in recipients:
            if not isinstance(recipient, RecipientInterface):
                raise ValueError("Invalid child recipient.")
            self._recipients.append(recipient)
        return

    @property
    def key(self) -> bytes:
        """
        The body of the key as bytes.
        """
        return self._key

    @property
    def protected(self) -> Dict[int, Any]:
        """
        The parameters that are to be cryptographically protected.
        """
        return self._protected

    @property
    def unprotected(self) -> Dict[int, Any]:
        """
        The parameters that are not cryptographically protected.
        """
        return self._unprotected

    @property
    def ciphertext(self) -> bytes:
        """
        The ciphertext encoded as bytes
        """
        return self._ciphertext

    @property
    def recipients(self) -> Union[List[Any], None]:
        """
        The list of recipient information structures.
        """
        return self._recipients

    def to_list(self) -> List[Any]:
        """
        Returns the recipient information as a COSE recipient structure.

        Returns:
            List[Any]: The recipient structure.
        """
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

    def set_key(self, key: bytes):
        """
        Sets a key.

        Args:
            key (bytes): The key as bytes.
        """
        self._key = key
        return

    def verify_key(
        self,
        material: bytes,
        expected_key: bytes,
        context: Union[List[Any], Dict[str, Any]],
    ):
        """
        Verifies a key with a key material and an expected key.

        Args:
            material (bytes): A key material.
            expected_key (bytes): A byte string of the expected key.
            context (Union[List[Any], Dict[str, Any]]): Context information structure.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            VerifyError: Failed to verify the key.
        """
        raise NotImplementedError

    def wrap_key(self, key_to_wrap: bytes):
        """
        Wraps a key and keeps it internally as the ciphertext.

        Args:
            key_to_wrap (bytes): A key to be wrapped.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to encode(wrap) key.
        """
        raise NotImplementedError

    def unwrap_key(self, alg: int) -> COSEKeyInterface:
        """
        Unwraps the key stored as the ciphertext.

        Args:
            alg (int): The algorithm of the wrapped key.
        Returns:
            COSEKeyInterface: An unwrapped key.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            DecodeError: Failed to decode(unwrap) the key.
        """
        raise NotImplementedError
