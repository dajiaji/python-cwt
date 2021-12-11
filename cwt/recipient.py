import json
from typing import Any, Dict, List, Optional, Union

import cbor2

from .const import (  # COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT,
    COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP,
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
from .recipient_interface import RecipientInterface
from .utils import parse_apu, parse_apv, to_cose_header


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
    ) -> RecipientInterface:
        """
        Creates a recipient from a CBOR-like dictionary with numeric keys.

        Args:
            protected (dict): Parameters that are to be cryptographically protected.
            unprotected (dict): Parameters that are not cryptographically protected.
            ciphertext (List[Any]): A cipher text.
            sender_key (Optional[COSEKeyInterface]): A sender key as COSEKey.
        Returns:
            RecipientInterface: A recipient object.
        Raises:
            ValueError: Invalid arguments.
        """
        p = to_cose_header(protected, algs=COSE_ALGORITHMS_RECIPIENT)
        u = to_cose_header(unprotected, algs=COSE_ALGORITHMS_RECIPIENT)

        alg = u[1] if 1 in u else p.get(1, 0)
        if alg == 0:
            raise ValueError("alg should be specified.")
        if alg == -6:
            return DirectKey(u, ciphertext, recipients)
        if alg in [-10, -11]:
            return DirectHKDF(p, u, ciphertext, recipients)
        if alg in [-3, -4, -5]:
            if not sender_key:
                sender_key = COSEKey.from_symmetric_key(alg=alg)
            return AESKeyWrap(p, u, sender_key, ciphertext, recipients)
        if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT.values():
            return ECDH_DirectHKDF(p, u, ciphertext, recipients, sender_key)
        if alg in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP.values():
            return ECDH_AESKeyWrap(p, u, ciphertext, recipients, sender_key)
        raise ValueError(f"Unsupported or unknown alg(1): {alg}.")

    @classmethod
    def from_jwk(cls, data: Union[str, bytes, Dict[str, Any]]) -> RecipientInterface:
        """
        Creates a recipient from JWK-like data.

        Args:
            data (Union[str, bytes, Dict[str, Any]]): JSON-formatted recipient data.
        Returns:
            RecipientInterface: A recipient object.
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
        sender_key = None
        if "alg" not in recipient:
            raise ValueError("alg should be specified.")
        if not isinstance(recipient["alg"], str):
            raise ValueError("alg should be str.")
        if recipient["alg"] not in COSE_ALGORITHMS_RECIPIENT:
            raise ValueError(f"Unsupported or unknown alg: {recipient['alg']}.")
        if recipient["alg"] == "direct":
            unprotected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]
        elif recipient["alg"] in COSE_ALGORITHMS_KEY_WRAP:
            unprotected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]
            sender_key = COSEKey.from_jwk(recipient)
        else:
            protected[1] = COSE_ALGORITHMS_RECIPIENT[recipient["alg"]]
        if recipient["alg"] in COSE_ALGORITHMS_CKDM_KEY_AGREEMENT.keys():
            sender_key = COSEKey.from_jwk(recipient)

        # kid
        if "kid" in recipient:
            if not isinstance(recipient["kid"], (str, bytes)):
                raise ValueError("kid should be str or bytes.")
            if isinstance(recipient["kid"], str):
                unprotected[4] = recipient["kid"].encode("utf-8")
            else:
                unprotected[4] = recipient["kid"]

        # salt
        if "salt" in recipient:
            if not isinstance(recipient["salt"], str):
                raise ValueError("salt should be str.")
            unprotected[-20] = recipient["salt"].encode("utf-8")

        # context
        if "context" in recipient:
            if not isinstance(recipient["context"], dict):
                raise ValueError("context should be dict.")
            apu = parse_apu(recipient["context"])
            if apu[0]:
                unprotected[-21] = apu[0]
            if apu[1]:
                unprotected[-22] = apu[1]
            if apu[2]:
                unprotected[-23] = apu[2]
            apv = parse_apv(recipient["context"])
            if apv[0]:
                unprotected[-24] = apv[0]
            if apv[1]:
                unprotected[-25] = apv[1]
            if apv[2]:
                unprotected[-26] = apv[2]

        return cls.new(protected, unprotected, sender_key=sender_key)

    @classmethod
    def from_list(cls, recipient: List[Any]) -> RecipientInterface:
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
            return Recipient.new(protected, recipient[1], recipient[2])
        if not isinstance(recipient[3], list):
            raise ValueError("recipients should be list.")
        recipients: List[RecipientInterface] = []
        for r in recipient[3]:
            recipients.append(cls.from_list(r))
        return cls.new(protected, recipient[1], recipient[2], recipients)
