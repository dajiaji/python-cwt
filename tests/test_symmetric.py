"""
Tests for SymmetricKey.
"""
from secrets import token_bytes

import pytest

from cwt.exceptions import DecodeError, VerifyError
from cwt.key_types.symmetric import AESCCMKey, HMACKey, SymmetricKey


class TestSymmetricKey:
    """
    Tests for SymmetricKey.
    """

    def test_symmetric_key_constructor_with_hmac_256_256(self):
        """"""
        key = SymmetricKey(
            {
                1: 4,
                -1: b"mysecret",
                3: 5,  # HMAC 256/256
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 5
        assert key.key_ops is None
        assert key.base_iv is None

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be Symmetric(4).",
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
                {1: 4},
                "k(-1) not found.",
            ),
            (
                {1: 4, -1: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: b"mysecret"},
                "alg(3) not found.",
            ),
        ],
    )
    def test_symmetric_key_constructor_with_invalid_args(self, invalid, msg):
        """"""
        with pytest.raises(ValueError) as err:
            SymmetricKey(invalid)
            pytest.fail("SymmetricKey should fail.")
        assert msg in str(err.value)


class TestHMACKey:
    """
    Tests for HMACKey.
    """

    def test_hmac_key_constructor_with_hmac_256_256(self):
        """"""
        key = HMACKey(
            {
                1: 4,
                -1: b"mysecret",
                3: 5,  # HMAC 256/256
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 5
        assert key.key_ops is None
        assert key.base_iv is None
        try:
            sig = key.sign(b"Hello world!")
            key.verify(b"Hello world!", sig)
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be Symmetric(4).",
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
                {1: 4},
                "k(-1) not found.",
            ),
            (
                {1: 4, -1: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: b"mysecret"},
                "alg(3) not found.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 3},
                "Unsupported or unknown alg(3) for HMAC.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 8},
                "Unsupported or unknown alg(8) for HMAC.",
            ),
        ],
    )
    def test_hmac_key_constructor_with_invalid_args(self, invalid, msg):
        """"""
        with pytest.raises(ValueError) as err:
            HMACKey(invalid)
            pytest.fail("HMACKey should fail.")
        assert msg in str(err.value)

    def test_hmac_key_verify_with_invalid_signature(self):
        """"""
        key = HMACKey(
            {
                1: 4,
                -1: b"mysecret",
                3: 5,  # HMAC 256/256
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 5
        assert key.key_ops is None
        assert key.base_iv is None
        sig = key.sign(b"Hello world!")
        with pytest.raises(VerifyError) as err:
            key.verify(b"Hello world!", sig + b"xxx")
        assert "Failed to compare digest." in str(err.value)


class TestAESCCMKey:
    """
    Tests for AESCCMKey.
    """

    def test_aesccm_key_constructor_with_aes_ccm_16_64_128(self):
        """"""
        key = AESCCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 10,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 10
        assert key.key_ops is None
        assert key.base_iv is None
        nonce = token_bytes(13)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be Symmetric(4).",
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
                {1: 4},
                "k(-1) not found.",
            ),
            (
                {1: 4, -1: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {1: 4, -1: b"mysecret"},
                "alg(3) not found.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 9},
                "Unsupported or unknown alg(9) for AES CCM.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 34},
                "Unsupported or unknown alg(34) for AES CCM.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 10},
                "The length of AES-CCM-16-64-128 key should be 16 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 11},
                "The length of AES-CCM-16-64-256 key should be 32 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 12},
                "The length of AES-CCM-64-64-128 key should be 16 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 13},
                "The length of AES-CCM-64-64-256 key should be 32 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 30},
                "The length of AES-CCM-16-128-128 key should be 16 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 31},
                "The length of AES-CCM-16-128-256 key should be 32 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 32},
                "The length of AES-CCM-64-128-128 key should be 16 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 33},
                "The length of AES-CCM-64-128-256 key should be 32 bytes.",
            ),
        ],
    )
    def test_aesccm_key_constructor_with_invalid_args(self, invalid, msg):
        """"""
        with pytest.raises(ValueError) as err:
            AESCCMKey(invalid)
            pytest.fail("AESCCMKey should fail.")
        assert msg in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_nonce(self):
        """"""
        key = AESCCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 10,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 10
        assert key.key_ops is None
        assert key.base_iv is None
        nonce = token_bytes(13)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(13))
        assert "Failed to decrypt." in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_length_nonce(self):
        """"""
        key = AESCCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 10,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 10
        assert key.key_ops is None
        assert key.base_iv is None
        nonce = token_bytes(13)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(ValueError) as err:
            key.decrypt(encrypted, nonce=token_bytes(7))
        assert "The length of nonce should be 13 bytes." in str(err.value)
