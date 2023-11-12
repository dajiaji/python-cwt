from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cbor2 import CBORTag, loads

from .cbor_processor import CBORProcessor
from .const import COSE_TAG_TO_TYPE, COSE_TYPE_TO_TAG
from .cose_key_interface import COSEKeyInterface
from .enums import COSETypes
from .signer import Signer


class COSEMessage(CBORProcessor):
    """
    The COSE message.
    """

    def __init__(self, type: COSETypes, msg: List[Any]):
        """
        Constructor.

        Args:
            type (List[Any]): A type of the COSE message.
            msg (List[Any]): A COSE message as a CBOR array.
        """
        self._validate_cose_message(msg)
        self._msg = msg
        self._type = type
        self._protected = msg[0]
        self._unprotected = msg[1]
        # self._payload = msg[2]  # msg[2] is mutable and has no readable alias to avoid complexity.
        self._other_fields: List[bytes] = []
        self._recipients: List[List[Any]] = []
        self._signatures: List[List[Any]] = []

        if self._type == COSETypes.ENCRYPT0:
            if len(self._msg) != 3:
                raise ValueError("Invalid COSE_Encrypt0 message.")

        elif self._type == COSETypes.ENCRYPT:
            if len(self._msg) != 4:
                raise ValueError("Invalid COSE_Encrypt message.")
            if not isinstance(self._msg[3], list):
                raise ValueError("The COSE recipients should be array.")
            for recipient in self._msg[3]:
                self._validate_cose_message(recipient)
            self._recipients = self._msg[3]

        elif self._type == COSETypes.MAC0:
            if len(self._msg) != 4:
                raise ValueError("Invalid COSE_Mac0 message.")
            if not isinstance(self._msg[3], bytes):
                raise ValueError("tag should be bytes.")
            self._other_fields = [self._msg[3]]  # tag

        elif self._type == COSETypes.MAC:
            if len(self._msg) != 5:
                raise ValueError("Invalid COSE_Mac message.")
            if not isinstance(self._msg[3], bytes):
                raise ValueError("The tag value should be bytes.")
            self._other_fields = [self._msg[3]]  # tag
            if not isinstance(self._msg[4], list):
                raise ValueError("The COSE recipients should be array.")
            for recipient in self._msg[4]:
                self._validate_cose_message(recipient)
            self._recipients = self._msg[4]

        elif self._type == COSETypes.SIGN1:
            if len(self._msg) != 4:
                raise ValueError("Invalid COSE_Sign1 message.")
            if not isinstance(self._msg[3], bytes):
                raise ValueError("The COSE signature should be bytes.")
            self._other_fields = [self._msg[3]]

        elif self._type == COSETypes.SIGN:
            if len(self._msg) != 4:
                raise ValueError("Invalid COSE_Sign message.")
            if not isinstance(self._msg[3], list):
                raise ValueError("The COSE signatures should be array.")
            for signature in self._msg[3]:
                self._validate_cose_message(signature)
            self._signatures = self._msg[3]

        elif self._type == COSETypes.COUNTERSIGNATURE:
            if len(self._msg) != 3:
                raise ValueError("Invalid COSE_Countersignature.")

        elif self._type == COSETypes.SIGNATURE:
            if len(self._msg) != 3:
                raise ValueError("Invalid COSE_Signature.")

        elif self._type == COSETypes.RECIPIENT:
            if len(self._msg) != 3:
                raise ValueError("Invalid COSE_Recipient.")

        else:
            raise ValueError(f"Invalid COSETypes({type}) for COSE message.")
        return

    def __eq__(self: COSEMessage, other: object) -> bool:
        if not isinstance(other, COSEMessage):
            return NotImplemented
        return self._type == other._type and self._msg == other._msg

    def __ne__(self: COSEMessage, other: object) -> bool:
        return not self.__eq__(other)

    @classmethod
    def loads(cls, msg: bytes):
        tagged = loads(msg)
        if not isinstance(tagged, CBORTag):
            raise ValueError("Invalid COSE format.")
        type = COSE_TAG_TO_TYPE.get(tagged.tag, None)
        if type is None:
            raise ValueError(f"Unknown CBOR tag for COSE message: {tagged.tag}.")
        return cls(type, tagged.value)

    @classmethod
    def from_cose_signature(cls, signature: List[Any]):
        return cls(COSETypes.SIGNATURE, signature)

    @classmethod
    def from_cose_recipient(cls, recipient: List[Any]):
        return cls(COSETypes.RECIPIENT, recipient)

    @property
    def type(self) -> COSETypes:
        """
        The identifier of the key type.
        """
        return self._type

    @property
    def protected(self) -> Dict[int, Any]:
        """
        The protected headers as a CBOR object.
        """
        return self._loads(self._protected)

    @property
    def unprotected(self) -> Dict[int, Any]:
        """
        The unprotected headers as a CBOR object.
        """
        return self._unprotected

    @property
    def payload(self) -> bytes:
        """
        The payload of the COSE message.
        """
        return self._msg[2]

    @property
    def other_fields(self) -> List[bytes]:
        """
        The list of other fields of the COSE message.
        """
        return self._other_fields

    @property
    def signatures(self) -> List[List[Any]]:
        """
        The list of signatures of the COSE message.
        """
        return self._signatures

    @property
    def recipients(self) -> List[List[Any]]:
        """
        The list of recipients of the COSE message.
        """
        return self._recipients

    def dumps(self) -> bytes:
        """
        Serializes the COSE message structure to a byte string.
        """
        tag = COSE_TYPE_TO_TAG.get(self._type, -1)
        return self._dumps(CBORTag(tag, self._msg)) if tag > 0 else self._dumps(self._msg)

    def countersign(
        self,
        signer: Signer,
        aad: bytes = b"",
        abbreviated: bool = False,
        tagged: bool = False,
        detached_payload: Optional[bytes] = None,
    ) -> COSEMessage:
        """
        Countersigns to the COSE message with the signer specified.

        Args:
            signer(Signer): A signer object that signs the COSE message.
            aad (bytes): The application supplied additional authenticated data.
            abbreviated(bool): The type of the countersignature (abbreviated or not).
            tagged(bool): The indicator whether the countersignature is tagged or not.
            detached_payload (Optional[bytes]): The detached payload that should be
                countersigned with the COSEMessage.
        Returns:
            COSEMessage: The COSE message (self).
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to countersign.
        """
        payload = self._msg[2]
        if detached_payload is not None:
            if self._msg[2] is not None:
                raise ValueError("The payload already exists.")
            payload = detached_payload

        if abbreviated:
            to_be_signed = [
                "CounterSignature0V2" if len(self._other_fields) > 0 else "CounterSignature0",
                self._protected,
                aad,
                payload,
            ]
            for other_field in self._other_fields:
                to_be_signed.append(other_field)
            signer.sign(self._dumps(to_be_signed))
            self._unprotected[12] = signer.signature
            return self

        to_be_signed = [
            "CounterSignatureV2" if len(self._other_fields) > 0 else "CounterSignature",
            self._protected,
            signer.protected,
            aad,
            payload,
        ]
        for other_field in self._other_fields:
            to_be_signed.append(other_field)
        signer.sign(self._dumps(to_be_signed))
        cs = self._unprotected.get(11, None)
        if not cs:
            self._unprotected[11] = [signer.protected, signer.unprotected, signer.signature]
            return self

        if isinstance(cs[0], bytes):
            self._unprotected[11] = [cs]
        self._unprotected[11].append([signer.protected, signer.unprotected, signer.signature])
        return self

    def counterverify(
        self,
        key: COSEKeyInterface,
        aad: bytes = b"",
        detached_payload: Optional[bytes] = None,
    ) -> Optional[List[Any]]:
        """
        Verifies a countersignature in the COSE message with the verification key specified.

        Args:
            key(COSEKeyInterface): A COSEKey that is used to verify a signature in the COSE message.
            aad (bytes): The application supplied additional authenticated data.
            detached_payload (Optional[bytes]): The detached payload that should be
                counterverified with the COSEMessage.
        Returns:
            Optional[List[Any]]: The COSE signature verified.
        Raises:
            ValueError: Invalid arguments.
            VerifyError: Failed to verify.
        """
        payload = self._msg[2]
        if detached_payload is not None:
            if self._msg[2] is not None:
                raise ValueError("The payload already exists.")
            payload = detached_payload

        err: Exception = ValueError("Countersignature not found.")
        acs = self._unprotected.get(12, None)
        if acs:
            to_be_signed = [
                "CounterSignature0V2" if len(self._other_fields) > 0 else "CounterSignature0",
                self._protected,
                aad,
                payload,
            ]
            for other_field in self._other_fields:
                to_be_signed.append(other_field)
            try:
                key.verify(self._dumps(to_be_signed), acs)
                return None
            except Exception as e:
                err = e

        cs = self._unprotected.get(11, None)
        if not cs:
            raise err
        to_be_signed = [
            "CounterSignatureV2" if len(self._other_fields) > 0 else "CounterSignature",
            self._protected,
            b"",
            aad,
            payload,
        ]
        for other_field in self._other_fields:
            to_be_signed.append(other_field)
        if isinstance(cs[0], bytes):
            kid = self._get_kid(cs)
            if key.kid and kid and key.kid != kid:
                raise ValueError("kid mismatch.")
            to_be_signed[2] = cs[0]
            key.verify(self._dumps(to_be_signed), cs[2])
            return cs
        for sig in cs:
            kid = self._get_kid(sig)
            if key.kid and kid and key.kid != kid:
                continue
            to_be_signed[2] = sig[0]
            try:
                key.verify(self._dumps(to_be_signed), sig[2])
                return sig
            except Exception as e:
                err = e
        raise err

    def _validate_cose_message(self, msg: List[Any]):
        if len(msg) < 3:
            raise ValueError("Invalid COSE message.")
        if not isinstance(msg[0], bytes):
            raise ValueError("The protected headers should be bytes.")
        if not isinstance(msg[1], dict):
            raise ValueError("The unprotected headers should be Dict[int, Any].")
        if not isinstance(msg[2], bytes) and msg[2] is not None:
            raise ValueError("The payload should be bytes or null.")

        countersignatures = msg[1].get(11, None)
        if countersignatures is None:
            return
        if not isinstance(countersignatures, list):
            raise ValueError("The countersignature should be array.")
        if len(countersignatures) == 0:
            raise ValueError("Invalid countersignature.")
        if isinstance(countersignatures[0], bytes):
            return self._validate_cose_message(countersignatures)
        elif not isinstance(countersignatures[0], list):
            raise ValueError("Invalid countersignature.")
        for cs in countersignatures:
            self._validate_cose_message(cs)
        return

    def _get_kid(self, sig: list) -> Optional[bytes]:
        kid = sig[1].get(4, None)
        return kid if kid else self._loads(sig[0]).get(4, None)

    def detach_payload(self) -> Tuple[COSEMessage, bytes]:
        """
        Detach a payload from the COSE message

        Returns:
            Tuple[COSEMessage, bytes]: The COSE message (self),
            and a byte string of the detached payload.
        Raises:
            ValueError: The payload does not exist.
        """

        if self._msg[2] is None:
            raise ValueError("The payload does not exist.")

        payload = self._msg[2]
        self._msg[2] = None
        return self, payload

    def attach_payload(self, payload: bytes) -> COSEMessage:
        """
        Attach a detached content to the COSE message

        Args:
            payload (bytes): A byte string of detached payload.
        Returns:
            COSEMessage: The COSE message (self).
        Raises:
            ValueError: The payload already exist.
        """

        if self._msg[2] is not None:
            raise ValueError("The payload already exists.")
        self._msg[2] = payload
        return self
