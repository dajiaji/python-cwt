"""
Tests for KeyWrap.
"""

from secrets import token_bytes

import pytest

from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError, EncodeError
from cwt.recipient_algs.aes_key_wrap import AESKeyWrap


class TestAESKeyWrap:
    """
    Tests for AESKeyWrap.
    """

    def test_aes_key_wrap_constructor_a128kw(self):
        ctx = AESKeyWrap({1: -3}, sender_key=COSEKey.from_symmetric_key(alg="A128KW"))
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -3

    def test_aes_key_wrap_constructor_a192kw(self):
        ctx = AESKeyWrap({1: -4}, sender_key=COSEKey.from_symmetric_key(alg="A192KW"))
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -4

    def test_aes_key_wrap_constructor_a256kw(self):
        ctx = AESKeyWrap({1: -5}, sender_key=COSEKey.from_symmetric_key(alg="A256KW"))
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -5

    def test_aes_key_wrap_constructor_a128kw_with_key(self):
        ctx = AESKeyWrap(
            {1: -3},
            sender_key=COSEKey.from_symmetric_key(alg="A128KW", key=token_bytes(16)),
        )
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -3

    def test_aes_key_wrap_constructor_a192kw_with_key(self):
        ctx = AESKeyWrap(
            {1: -4},
            sender_key=COSEKey.from_symmetric_key(alg="A192KW", key=token_bytes(24)),
        )
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -4

    def test_aes_key_wrap_constructor_a256kw_with_key(self):
        ctx = AESKeyWrap(
            {1: -5},
            sender_key=COSEKey.from_symmetric_key(alg="A256KW", key=token_bytes(32)),
        )
        assert isinstance(ctx, AESKeyWrap)
        assert ctx.alg == -5

    def test_aes_key_wrap_constructor_without_sender_key(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {1: -3},
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert "sender_key should be set." in str(err.value)

    def test_aes_key_wrap_constructor_a128kw_with_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {1: -3},
                sender_key=COSEKey.from_symmetric_key(key="xxx", alg="A128KW"),
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a192kw_with_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {1: -4},
                sender_key=COSEKey.from_symmetric_key(key="xxx", alg="A192KW"),
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a256kw_invalid_key_length(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {1: -5},
                sender_key=COSEKey.from_symmetric_key(key="xxx", alg="A256KW"),
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid key length: 3." in str(err.value)

    def test_aes_key_wrap_constructor_a128kw_with_invalid_alg_in_sender_key(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {1: -3},
                sender_key=COSEKey.from_symmetric_key(alg="A128GCM"),
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert "Invalid alg in sender_key: 1." in str(err.value)

    def test_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({1: -1}, sender_key=COSEKey.from_symmetric_key(alg="A128KW"))
            pytest.fail("AESKeyWrap() should fail.")
        assert "alg in unprotected and sender_key's alg do not match." in str(err.value)

    # def test_aes_key_wrap_encode_with_invalid_key(self):
    #     key = COSEKey.from_symmetric_key(key="xxx", alg="HS256", kid="01")
    #     ctx = AESKeyWrap({1: -3}, {}, sender_key=COSEKey.from_symmetric_key(alg="A128KW"), context={"alg": "A128GCM"})
    #     with pytest.raises(EncodeError) as err:
    #         ctx.encode(key)
    #         pytest.fail("encode() should fail.")
    #     assert "Failed to wrap key." in str(err.value)

    def test_aes_key_wrap_encode_without_key(self):
        ctx = AESKeyWrap({1: -3}, sender_key=COSEKey.from_symmetric_key(alg="A128KW"))
        with pytest.raises(EncodeError) as err:
            ctx.encode()
            pytest.fail("encode() should fail.")
        assert "Failed to wrap key." in str(err.value)

    def test_aes_key_wrap_wrap_key_without_alg(self):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        key = COSEKey.from_symmetric_key(alg="A128KW", kid="01")
        ctx = AESKeyWrap({1: -3}, sender_key=key)
        ctx.encode(enc_key.to_bytes())
        with pytest.raises(ValueError) as err:
            ctx.decode(key=key, as_cose_key=True)
            pytest.fail("decode() should fail.")
        assert "alg should be set." in str(err.value)

    def test_aes_key_wrap_wrap_key_without_ciphertext(self):
        key = COSEKey.from_symmetric_key(alg="A128GCM", kid="01")
        ctx = AESKeyWrap({1: -3}, sender_key=COSEKey.from_symmetric_key(alg="A128KW"))
        with pytest.raises(DecodeError) as err:
            ctx.decode(key=key, alg="A128GCM", as_cose_key=True)
            pytest.fail("decode() should fail.")
        assert "Failed to decode key." in str(err.value)
