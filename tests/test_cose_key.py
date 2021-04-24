# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEKey.
"""
import pytest

from cwt import COSEKey

# from secrets import token_bytes


# from .utils import key_path


class TestCOSEKey:
    """
    Tests for COSEKey.
    """

    def test_cose_key_constructor(self):
        """"""
        key = COSEKey({1: 1, 2: b"123", 3: 1})
        assert key.kty == 1
        assert key.kid == b"123"
        assert key.alg == 1
        assert key.key_ops is None
        assert key.base_iv is None
        with pytest.raises(NotImplementedError):
            key.sign(b"message")
            pytest.fail("COSEKey.sign() should fail.")
        with pytest.raises(NotImplementedError):
            key.verify(b"message", b"signature")
            pytest.fail("COSEKey.verify() should fail.")
        with pytest.raises(NotImplementedError):
            key.encrypt(b"message", nonce=b"123", aad=None)
            pytest.fail("COSEKey.encrypt() should fail.")
        with pytest.raises(NotImplementedError):
            key.decrypt(b"message", nonce=b"123", aad=None)
            pytest.fail("COSEKey.decrypt() should fail.")

    def test_cose_key_constructor_without_cose_key(self):
        """"""
        with pytest.raises(TypeError):
            COSEKey()
            pytest.fail("COSEKey should fail.")

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
        """"""
        with pytest.raises(ValueError) as err:
            COSEKey(invalid)
            pytest.fail("COSEKey should fail.")
        assert msg in str(err.value)
