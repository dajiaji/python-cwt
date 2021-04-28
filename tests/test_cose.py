# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import cbor2
import pytest
from cbor2 import CBORTag

from cwt import COSE, cose_key

from .utils import key_path


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return COSE()


class TestCOSE:
    """
    Tests for COSE.
    """

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                "invalid_string_data",
                "Invalid COSE format.",
            ),
            (
                {},
                "Invalid COSE format.",
            ),
            (
                [],
                "Invalid COSE format.",
            ),
            (
                123,
                "Invalid COSE format.",
            ),
            (
                cbor2.CBORTag(16, "invalid_string_data"),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, {}),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, []),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, 123),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, [b"", b"invalid byte data", b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", "invalid string data", b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", [], b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", 123, b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.dumps(CBORTag(96, [])),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, {})),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, b"")),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, 123)),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, [b"", b"", b""])),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, [b"", b"", b"", [b""]])),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(17, "invalid_string_data"),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, {}),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, []),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, 123),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(97, "invalid_string_data"),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, {}),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, []),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, 123),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(18, "invalid_string_data"),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, {}),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, []),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, 123),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [])),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, {})),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, b"")),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, 123)),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", b"", b"", b""])),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", b"", b"", [b""]])),
                "Invalid Signature format.",
            ),
        ],
    )
    def test_cose_decode_with_invalid_data(self, ctx, invalid, msg):
        """"""
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read(), kid="1")

        with pytest.raises(ValueError) as err:
            ctx.decode(invalid, public_key)
            pytest.fail("decode should fail.")
        assert msg in str(err.value)
