"""
Tests for KeyWrap.
"""

import pytest

from cwt.algs.symmetric import AESKeyWrap
from cwt.exceptions import DecodeError


class TestAESKeyWrap:
    """
    Tests for AESKeyWrap.
    """

    def test_aes_key_wrap_constructor_a128kw(self):
        key = AESKeyWrap({1: 4, 3: -3})
        assert key.alg == -3

    def test_aes_key_wrap_constructor_a192kw(self):
        key = AESKeyWrap({1: 4, 3: -4})
        assert isinstance(key, AESKeyWrap)
        assert key.alg == -4

    def test_aes_key_wrap_constructor_a256kw(self):
        key = AESKeyWrap({1: 4, 3: -5})
        assert isinstance(key, AESKeyWrap)
        assert key.alg == -5

    def test_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: 4, 3: 1})
            pytest.fail("AESKeyWrap() should fail.")
        assert "Unknown alg(3) for AES key wrap: 1." in str(err.value)

    def test_aes_key_wrap_constructor_with_invalid_key_ops(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: 4, 3: -3, 4: [1, 2]})
            pytest.fail("AESKeyWrap() should fail.")
        assert "Unknown or not permissible key_ops(4) for AES key wrap: 1." in str(err.value)

    def test_aes_key_wrap_unwrap_key_with_invalid_alg(self):
        key = AESKeyWrap({1: 4, 3: -3})
        with pytest.raises(DecodeError) as err:
            key.unwrap_key(b"")
            pytest.fail("unwrap_key() should fail.")
        assert "Failed to unwrap key." in str(err.value)
