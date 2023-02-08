from typing import Any, Dict, List

from certvalidator import CertificateValidator, ValidationContext

from ..cose_key_interface import COSEKeyInterface
from ..exceptions import VerifyError


class AsymmetricKey(COSEKeyInterface):
    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)

        self._key: Any = b""
        self._cert = b""
        self._intermediates = []

        if 33 in params:
            if not isinstance(params[33], (bytes, list)):
                raise ValueError("x5c(33) should be bytes(bstr) or list.")
            certs = [params[33]] if isinstance(params[33], bytes) else params[33]
            self._cert = certs[0]
            if len(certs) > 1:
                self._intermediates = certs[1:]
            return

    def validate_certificate(self, ca_certs: List[bytes]) -> bool:
        if not ca_certs:
            raise ValueError("ca_certs should be set.")
        if not self._cert:
            return False

        ctx = ValidationContext(trust_roots=ca_certs)
        try:
            validator = CertificateValidator(self._cert, self._intermediates, validation_context=ctx)
            validator.validate_usage(set(["digital_signature"]), extended_optional=True)
        except Exception as err:
            raise VerifyError("Failed to validate the certificate bound to the key.") from err
        return True
