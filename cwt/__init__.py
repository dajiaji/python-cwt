from .claims import Claims
from .cose import COSE
from .cose_key import COSEKey
from .cwt import (
    CWT,
    decode,
    encode,
    encode_and_encrypt,
    encode_and_mac,
    encode_and_sign,
    set_private_claim_names,
)
from .encrypted_cose_key import EncryptedCOSEKey
from .exceptions import CWTError, DecodeError, EncodeError, VerifyError
from .recipient import Recipient
from .signer import Signer

__version__ = "0.10.0"
__title__ = "cwt"
__description__ = "A Python implementation of CWT/COSE"
__url__ = "https://python-cwt.readthedocs.io"
__uri__ = __url__
__doc__ = __description__ + " <" + __uri__ + ">"
__author__ = "AJITOMI Daisuke"
__email__ = "ajitomi@gmail.com"
__license__ = "MIT"
__copyright__ = "Copyright 2021 AJITOMI Daisuke"
__all__ = [
    "encode",
    "encode_and_mac",
    "encode_and_sign",
    "encode_and_encrypt",
    "decode",
    "set_private_claim_names",
    "CWT",
    "COSE",
    "COSEKey",
    "EncryptedCOSEKey",
    "Claims",
    "Recipient",
    "Signer",
    "CWTError",
    "EncodeError",
    "DecodeError",
    "VerifyError",
]
