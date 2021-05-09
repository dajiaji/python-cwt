import json
from typing import Any, Dict, Optional, Union

from .claims import Claims
from .const import CWT_CLAIM_NAMES
from .key_builder import KeyBuilder


class ClaimsBuilder:
    """
    CBOR Web Token (CWT) Claims Builder.

    ``cwt.claims`` is a global object of this class initialized with default settings.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Constructor.

        At the current implementation, any ``options`` will be ignored.
        """
        self._options = options
        self._key_builder = KeyBuilder()
        self._private_claim_names: Dict[str, int] = {}
        self._claim_names = dict(CWT_CLAIM_NAMES, **self._private_claim_names)
        return

    def from_dict(self, claims: Dict[int, Any]) -> Claims:
        """
        Create a Claims object from a CBOR-like(Dict[int, Any]) claim object.


        Args:
            claims (Dict[str, Any]): A CBOR-like(Dict[int, Any]) claim object.

        Returns:
            Claims: A CWT claims object.

        Raises:
            ValueError: Invalid arguments.
        """
        return Claims(claims, self._claim_names)

    def from_json(self, claims: Union[str, bytes, Dict[str, Any]]) -> Claims:
        """
        Converts a JWT claims object into a CWT claims object which has numeric
        keys. If a key string in JSON data cannot be mapped to a numeric key,
        it will be skipped.

        Args:
            claims (Union[str, bytes, Dict[str, Any]]): A JWT claims object
                to be converted.

        Returns:
            Claims: A CWT claims object.

        Raises:
            ValueError: Invalid arguments.
        """
        json_claims: Dict[str, Any] = {}
        if isinstance(claims, str) or isinstance(claims, bytes):
            json_claims = json.loads(claims)
        else:
            json_claims = claims

        for k in json_claims:
            if not isinstance(k, int):
                break
            raise ValueError("It is already CBOR-like format.")

        # Convert JSON to CBOR (Convert the type of key from str to int).
        cbor_claims: Dict[int, Any] = {}
        for k, v in json_claims.items():
            if k not in CWT_CLAIM_NAMES:
                if k in self._private_claim_names:
                    cbor_claims[self._private_claim_names[k]] = v
            elif k == "cnf":
                if not isinstance(v, dict):
                    raise ValueError("cnf value should be dict.")
                if "jwk" in v:
                    key = self._key_builder.from_jwk(v["jwk"])
                    cbor_claims[CWT_CLAIM_NAMES[k]] = {1: key.to_dict()}
                elif "eck" in v:
                    cbor_claims[CWT_CLAIM_NAMES[k]] = {2: v["eck"]}
                elif "kid" in v:
                    cbor_claims[CWT_CLAIM_NAMES[k]] = {3: v["kid"].encode("utf-8")}
                else:
                    raise ValueError("Supported cnf value not found.")
            else:
                cbor_claims[CWT_CLAIM_NAMES[k]] = v

        # Convert test string should be bstr into bstr.
        # -259: EUPHNonce
        # -258: EATMAROEPrefix
        #    7: cti
        for i in [-259, -258, 7]:
            if i in cbor_claims and isinstance(cbor_claims[i], str):
                cbor_claims[i] = cbor_claims[i].encode("utf-8")
        return Claims(cbor_claims, self._claim_names)

    def set_private_claim_names(self, claim_names: Dict[str, int]):
        """
        Sets private claim definitions. The definitions will be used
        in :func:`from_json <cwt.ClaimsBuilder.from_json>`.

        Args:
            claims (Dict[str, int]): A set of private claim definitions which
                consist of a readable claim name(str) and a claim key(int).
                The claim key should be less than -65536 but you  can use the
                numbers other than pre-registered numbers listed in
                `IANA Registry <https://www.iana.org/assignments/cose/cose.xhtml>`_.
        Raises:
            ValueError: Invalid arguments.
        """
        for v in claim_names.values():
            if v in CWT_CLAIM_NAMES.values():
                raise ValueError(
                    "The claim key should be other than the values listed in https://python-cwt.readthedocs.io/en/stable/claims.html."
                )
        self._private_claim_names = claim_names
        self._claim_names = dict(CWT_CLAIM_NAMES, **self._private_claim_names)
        return

    def validate(self, claims: Dict[int, Any]):
        """
        Validates a CWT claims object.

        Args:
            claims (Dict[int, Any]): A CWT claims object to be validated.

        Raises:
            ValueError: Failed to verify.
        """
        Claims(claims)
        return


# export
claims = ClaimsBuilder()
