from typing import Any, Dict, List

from cryptography.x509 import Certificate, DNSName, load_der_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store

from ..cose_key_interface import COSEKeyInterface
from ..exceptions import VerifyError


class AsymmetricKey(COSEKeyInterface):
    def __init__(self, params: Dict[int, Any]):
        super().__init__(params)

        self._key: Any = b""
        self._cert: Certificate = None
        self._intermediates: List[Certificate] = []

        if 33 in params:
            if not isinstance(params[33], (bytes, list)):
                raise ValueError("x5c(33) should be bytes(bstr) or list.")
            certs = [params[33]] if isinstance(params[33], bytes) else params[33]
            self._cert = load_der_x509_certificate(certs[0])
            if len(certs) > 1:
                for c in certs[1:]:
                    self._intermediates.append(load_der_x509_certificate(c))
            return

    def validate_certificate(self, ca_certs: List[Certificate]) -> bool:
        if not ca_certs:
            raise ValueError("ca_certs should be set.")
        if not self._cert:
            return False

        store = Store(ca_certs)
        builder = PolicyBuilder().store(store)
        verifier = builder.build_server_verifier(
            DNSName(self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        )
        try:
            verifier.verify(self._cert, self._intermediates)
        except Exception as err:
            raise VerifyError("Failed to validate the certificate bound to the key.") from err
        return True
