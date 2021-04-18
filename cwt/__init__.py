from .claims import Claims, claims
from .cose import COSE
from .cose_key import COSEKey
from .cwt import CWT, decode, encode_and_encrypt, encode_and_mac, encode_and_sign
from .exceptions import CWTError, DecodeError, EncodeError, VerifyError
from .key_builder import KeyBuilder, cose_key

__version__ = "0.2.1"
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
    "encode_and_mac",
    "encode_and_sign",
    "encode_and_encrypt",
    "decode",
    "CWT",
    "COSE",
    "Claims",
    "COSEKey",
    "KeyBuilder",
    "cose_key",
    "claims",
    "CWTError",
    "EncodeError",
    "DecodeError",
    "VerifyError",
]
