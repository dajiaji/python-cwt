from typing import Any, Dict, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256

from ..algs.ec2 import EC2Key
from ..const import COSE_KEY_TYPES
from ..cose_key import COSEKey
from ..cose_key_interface import COSEKeyInterface
from ..utils import uint_to_bytes


def _generate_kid(cert: bytes) -> bytes:
    c = x509.load_pem_x509_certificate(cert)
    fp = c.fingerprint(SHA256())
    return fp[0:8]


def load_pem_hcert_dsc(cert: Union[str, bytes]) -> COSEKeyInterface:
    """
    Loads PEM-formatted DSC (Digital Signing Certificate) issued by CSCA
    (Certificate Signing Certificate Authority) as a COSEKey. At this time,
    the kid of the COSE key will be generated as a 8-byte truncated SHA256
    fingerprint of the DSC complient with `Electronic Health Certificate
    Specification <https://github.com/ehn-dcc-development/hcert-spec/blob/main/hcert_spec.md>`_.

    Args:
        cert(str): A DSC.
    Returns:
        COSEKeyInterface: A DSC's public key as a COSE key.
    """
    if isinstance(cert, str):
        cert = cert.encode("utf-8")
    k: Any = None
    if b"BEGIN CERTIFICATE" in cert:
        k = x509.load_pem_x509_certificate(cert).public_key()
    else:
        raise ValueError("Invalid PEM data.")
    params: Dict[int, Any] = {}
    params[2] = _generate_kid(cert)

    if isinstance(k, RSAPublicKey):
        alg = -37  # "PS256"
        params[1] = COSE_KEY_TYPES["RSA"]
        params[3] = alg
        pub_nums = k.public_numbers()
        params[-1] = uint_to_bytes(pub_nums.n)
        params[-2] = uint_to_bytes(pub_nums.e)
    elif isinstance(k, EllipticCurvePublicKey):
        alg = -7  # "ES256"
        params[3] = alg
        params.update(EC2Key.to_cose_key(k))
    else:
        raise ValueError(f"Unsupported or unknown key type: {type(k)}.")
    return COSEKey.new(params)
