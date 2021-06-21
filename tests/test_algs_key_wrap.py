"""
Tests for KeyWrap.
"""

import pytest

from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError, EncodeError
from cwt.recipient_algs.aes_key_wrap import AESKeyWrap


class TestAESKeyWrap:
    """
    Tests for AESKeyWrap.
    """

    def test_aes_key_wrap_constructor_a128kw(self):
        ctx = AESKeyWrap({1: -3}, {})
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -3

    def test_aes_key_wrap_constructor_a192kw(self):
        ctx = AESKeyWrap({1: -4}, {})
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -4

    def test_aes_key_wrap_constructor_a256kw(self):
        ctx = AESKeyWrap({1: -5}, {})
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -5

    def test_aes_key_wrap_constructor_a128kw_with_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -3}, {}, key=b"xxx")
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a192kw_with_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -4}, {}, key=b"xxx")
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a256kw_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -5}, {}, key=b"xxx")
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -1}, {})
            pytest.fail("AESKeyWrap() should fail.")
        assert "Unknown alg(3) for AES key wrap: -1." in str(err.value)

    def test_aes_key_wrap_encode_key_with_invalid_key(self):
        key = COSEKey.from_symmetric_key(key="xxx", alg="HS256", kid="01")
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(EncodeError) as err:
            ctx.encode_key(key, alg="A128GCM")
            pytest.fail("encode_key() should fail.")
        assert "Failed to wrap key." in str(err.value)

    def test_aes_key_wrap_encode_key_without_key(self):
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(ValueError) as err:
            ctx.encode_key()
            pytest.fail("encode_key() should fail.")
        assert "key should be set." in str(err.value)

    def test_aes_key_wrap_wrap_key_without_alg(self):
        key = COSEKey.from_symmetric_key(alg="A128GCM", kid="01")
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(ValueError) as err:
            ctx.decode_key(key=key)
            pytest.fail("decode_key() should fail.")
        assert "alg should be set." in str(err.value)

    def test_aes_key_wrap_wrap_key_without_ciphertext(self):
        key = COSEKey.from_symmetric_key(alg="A128GCM", kid="01")
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(DecodeError) as err:
            ctx.decode_key(key=key, alg="A128GCM")
            pytest.fail("decode_key() should fail.")
        assert "Failed to decode key." in str(err.value)
