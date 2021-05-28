"""
Tests for KeyWrap.
"""

import pytest

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
            pytest.fail("AESKeyWrap should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a192kw_with_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -4}, {}, key=b"xxx")
            pytest.fail("AESKeyWrap should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a256kw_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -5}, {}, key=b"xxx")
            pytest.fail("AESKeyWrap should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -1}, {})
            pytest.fail("AESKeyWrap should fail.")
        assert "Unknown alg(3) for AES key wrap: -1." in str(err.value)

    def test_aes_key_wrap_wrap_key_with_invalid_key_to_wrap(self):
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(EncodeError) as err:
            ctx.wrap_key(b"")
            pytest.fail("wrap_key should fail.")
        assert "Failed to wrap key." in str(err.value)

    def test_aes_key_wrap_wrap_key_without_key_and_ciphertext(self):
        ctx = AESKeyWrap({1: -3}, {})
        with pytest.raises(DecodeError) as err:
            ctx.unwrap_key(10)
            pytest.fail("unwrap_key should fail.")
        assert "Failed to unwrap key." in str(err.value)
