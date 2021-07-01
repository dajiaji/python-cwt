from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256

from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface


def _generate_kid(cert: str) -> bytes:
    c = x509.load_pem_x509_certificate(cert.encode())
    fp = c.fingerprint(SHA256())
    return fp[0:8]


def load_pem_dgc_dsc(cert: str) -> COSEKeyInterface:
    """
    Loads PEM-formatted DSC (Digital Signing Certificate) issued by CSCA
    (Certificate Signing Certificate Authority) as a COSEKey. At this time,
    the kid of the COSE key will be generated as a 8-byte truncated SHA256
    fingerprint of the DSC complient with `Technical Specifications of Digital
    Green Certificates Volume 1
    <https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf>`_.

    Args:
        cert(str): A DSC.
    Returns:
        COSEKeyInterface: A DSC's public key as a COSE key.
    """
    return COSEKey.from_pem(cert, kid=_generate_kid(cert))
