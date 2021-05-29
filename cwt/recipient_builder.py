import json
from typing import Any, Dict, List, Union

from .const import (
    COSE_ALGORITHMS_KEY_WRAP,
    COSE_ALGORITHMS_RECIPIENT,
    COSE_KEY_OPERATION_VALUES,
)
from .recipient import Recipient
from .recipient_algs.aes_key_wrap import AESKeyWrap
from .recipient_algs.direct_hkdf import DirectHKDF
from .recipient_algs.direct_key import DirectKey
from .utils import base64url_decode


class RecipientBuilder:
    """
    A :class:`Recipient <cwt.Recipient>` Builder.
    """

    @classmethod
    def from_dict(
        cls,
        protected: Dict[int, Any],
        unprotected: Dict[int, Any],
        ciphertext: bytes = b"",
        recipients: List[Any] = [],
        key_ops: List[int] = [],
        key: bytes = b"",
    ) -> Recipient:
        """
        Create a recipient from a CBOR-like dictionary with numeric keys.

        Args:
            protected (Dict[int, Any]): Parameters that are to be cryptographically protected.
            unprotected (Dict[int, Any]): Parameters that are not cryptographically protected.
        Returns:
            Recipient: A recipient object.
        Raises:
            ValueError: Invalid arguments.
        """
        alg = unprotected[1] if 1 in unprotected else protected.get(1, 0)
        if alg == 0:
            raise ValueError("alg should be specified.")
        if alg == -6:
            return DirectKey(unprotected, ciphertext, recipients)
        if alg in [-10, -11]:
            return DirectHKDF(protected, unprotected, ciphertext, recipients)
        if alg in [-3, -4, -5]:
            return AESKeyWrap(
                protected, unprotected, ciphertext, recipients, key_ops, key
            )
        raise ValueError(f"Unsupported or unknown alg(1): {alg}.")

    @classmethod
    def from_json(cls, data: Union[str, bytes, Dict[str, Any]]) -> Recipient:
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
        key = b""
        key_ops = []

        if not isinstance(data, dict):
            recipient = json.loads(data)
        else:
            recipient = data

        # salt
        if "salt" in recipient:
            if not isinstance(recipient["salt"], str):
                raise ValueError("salt should be str.")
            unprotected[-20] = recipient["salt"].encode("utf-8")

        # alg
        if "alg" in recipient:
            if not isinstance(recipient["alg"], str):
                raise ValueError("alg should be str.")
            if recipient["alg"] not in COSE_ALGORITHMS_RECIPIENT:
                raise ValueError(f"Unsupported or unknown alg: {recipient['alg']}.")
            if recipient["alg"] == "direct":
                unprotected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]
            elif recipient["alg"] in COSE_ALGORITHMS_KEY_WRAP:
                unprotected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]
            else:
                protected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]

        # kid
        if "kid" in recipient:
            if not isinstance(recipient["kid"], str):
                raise ValueError("kid should be str.")
            unprotected[4] = recipient["kid"].encode("utf-8")

        # key_ops
        if "key_ops" in recipient:
            if not isinstance(recipient["key_ops"], list):
                raise ValueError("key_ops should be list.")
            for ops in recipient["key_ops"]:
                if not isinstance(ops, str):
                    raise ValueError("Each value of key_ops should be str.")
                try:
                    key_ops.append(COSE_KEY_OPERATION_VALUES[ops])
                except Exception:
                    raise ValueError(f"Unknown key_ops: {ops}.")

        # k
        if "k" in recipient:
            if not isinstance(recipient["k"], str):
                raise ValueError("k should be str.")
            key = base64url_decode(recipient["k"])

        return cls.from_dict(protected, unprotected, key_ops=key_ops, key=key)