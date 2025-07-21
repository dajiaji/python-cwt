# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEKeyInterface.
"""
import pytest

from cwt.cose_key_interface import COSEKeyInterface
from cwt.enums import COSEAlgs, COSEKeyParams, COSEKeyTypes

# from secrets import token_bytes


# from .utils import key_path


class TestCOSEKeyInterface:
    """
    Tests for COSEKeyInterface.
    """

    def test_cose_key_constructor(self):
        key = COSEKeyInterface({COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: b"123"})
        assert key.kty == COSEKeyTypes.OKP
        assert key.kid == b"123"
        assert key.key_ops == []
        assert key.base_iv is None
        raw = key.to_dict()
        assert raw[COSEKeyParams.KTY] == COSEKeyTypes.OKP
        assert raw[COSEKeyParams.KID] == b"123"
        with pytest.raises(NotImplementedError):
            key.key
            pytest.fail("COSEKeyInterface.key should fail.")
        with pytest.raises(NotImplementedError):
            key.generate_nonce()
            pytest.fail("COSEKeyInterface.generate_nonce() should fail.")
        with pytest.raises(NotImplementedError):
            key.sign(b"message")
            pytest.fail("COSEKeyInterface.sign() should fail.")
        with pytest.raises(NotImplementedError):
            key.verify(b"message", b"signature")
            pytest.fail("COSEKeyInterface.verify() should fail.")
        with pytest.raises(NotImplementedError):
            key.encrypt(b"message", nonce=b"123", aad=None)
            pytest.fail("COSEKeyInterface.encrypt() should fail.")
        with pytest.raises(NotImplementedError):
            key.decrypt(b"message", nonce=b"123", aad=None)
            pytest.fail("COSEKeyInterface.decrypt() should fail.")
        with pytest.raises(NotImplementedError):
            key.wrap_key(b"key_to_wrap")
            pytest.fail("COSEKeyInterface.decrypt() should fail.")
        with pytest.raises(NotImplementedError):
            key.unwrap_key(b"wrapped_key")
            pytest.fail("COSEKeyInterface.decrypt() should fail.")
        with pytest.raises(NotImplementedError):
            key.derive_bytes(16, b"material")
            pytest.fail("COSEKeyInterface.derive_bytes() should fail.")
        with pytest.raises(NotImplementedError):
            key.validate_certificate("/path/to/ca_certs")
            pytest.fail("COSEKeyInterface.validate_certificate() should fail.")

    def test_cose_key_constructor_with_alg_and_iv(self):
        key = COSEKeyInterface(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.KID: b"123",
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.BASE_IV: b"aabbccddee",
            }
        )
        assert key.base_iv == b"aabbccddee"
        raw = key.to_dict()
        assert raw[COSEKeyParams.BASE_IV] == b"aabbccddee"

    def test_cose_key_constructor_without_cose_key(self):
        with pytest.raises(TypeError):
            COSEKeyInterface()
            pytest.fail("COSEKeyInterface should fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {},
                "kty(1) not found.",
            ),
            (
                {COSEKeyParams.KTY: b"invalid"},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: {}},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: []},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: "xxx"},
                "Unknown kty: xxx",
            ),
            (
                {COSEKeyParams.KTY: 0},
                "Unknown kty: 0",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: "123"},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: {}},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: []},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: b"123", COSEKeyParams.ALG: b"HMAC 256/256"},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: b"123", COSEKeyParams.ALG: {}},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.KID: b"123", COSEKeyParams.ALG: []},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.KID: b"123",
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.KEY_OPS: "sign",
                },
                "key_ops(4) should be list.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.KID: b"123",
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.KEY_OPS: b"sign",
                },
                "key_ops(4) should be list.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.KID: b"123",
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.KEY_OPS: {},
                },
                "key_ops(4) should be list.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.KID: b"123",
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.KEY_OPS: [],
                    COSEKeyParams.BASE_IV: "xxx",
                },
                "Base IV(5) should be bytes(bstr).",
            ),
        ],
    )
    def test_cose_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKeyInterface(invalid)
            pytest.fail("COSEKeyInterface should fail.")
        assert msg in str(err.value)
