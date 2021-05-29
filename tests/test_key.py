# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEKeyInterface.
"""
import pytest

from cwt.cose_key_interface import COSEKeyInterface

# from secrets import token_bytes


# from .utils import key_path


class TestCOSEKeyInterface:
    """
    Tests for COSEKeyInterface.
    """

    def test_cose_key_constructor(self):
        key = COSEKeyInterface({1: 1, 2: b"123"})
        assert key.kty == 1
        assert key.kid == b"123"
        assert key.key_ops == []
        assert key.base_iv is None
        raw = key.to_dict()
        assert raw[1] == 1
        assert raw[2] == b"123"
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

    def test_cose_key_constructor_with_alg_and_iv(self):
        key = COSEKeyInterface({1: 1, 2: b"123", 3: 1, 5: b"aabbccddee"})
        assert key.base_iv == b"aabbccddee"
        raw = key.to_dict()
        assert raw[5] == b"aabbccddee"

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
                {1: b"invalid"},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: {}},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: []},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: "xxx"},
                "Unknown kty: xxx",
            ),
            (
                {1: 0},
                "Unknown kty: 0",
            ),
            (
                {1: 1, 2: "123"},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {1: 1, 2: {}},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {1: 1, 2: []},
                "kid(2) should be bytes(bstr).",
            ),
            (
                {1: 1, 2: b"123", 3: b"HMAC 256/256"},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {1: 1, 2: b"123", 3: {}},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {1: 1, 2: b"123", 3: []},
                "alg(3) should be int or str(tstr).",
            ),
            (
                {1: 1, 2: b"123", 3: 1, 4: "sign"},
                "key_ops(4) should be list.",
            ),
            (
                {1: 1, 2: b"123", 3: 1, 4: b"sign"},
                "key_ops(4) should be list.",
            ),
            (
                {1: 1, 2: b"123", 3: 1, 4: {}},
                "key_ops(4) should be list.",
            ),
            (
                {1: 1, 2: b"123", 3: 1, 4: [], 5: "xxx"},
                "Base IV(5) should be bytes(bstr).",
            ),
        ],
    )
    def test_cose_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKeyInterface(invalid)
            pytest.fail("COSEKeyInterface should fail.")
        assert msg in str(err.value)
