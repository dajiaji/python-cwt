"""
Tests for SymmetricKey.
"""
from secrets import token_bytes

import pytest

from cwt.algs.symmetric import AESCCMKey, AESGCMKey, ChaCha20Key, HMACKey, SymmetricKey
from cwt.exceptions import DecodeError, EncodeError, VerifyError


class TestSymmetricKey:
    """
    Tests for SymmetricKey.
    """

    def test_symmetric_key_constructor_with_hmac_256_256(self):
        key = SymmetricKey(
            {
                1: 4,
                -1: b"mysecret",
                3: 5,  # HMAC 256/256
            }
        )
        assert key.key == b"mysecret"
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 5
        assert key.key_ops == []
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
        with pytest.raises(ValueError) as err:
            SymmetricKey(invalid)
            pytest.fail("SymmetricKey should fail.")
        assert msg in str(err.value)


class TestHMACKey:
    """
    Tests for HMACKey.
    """

    def test_hmac_key_constructor_with_hmac_256_256(self):
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
        assert len(key.key_ops) == 2
        assert 9 in key.key_ops
        assert 10 in key.key_ops
        assert key.base_iv is None
        try:
            sig = key.sign(b"Hello world!")
            key.verify(b"Hello world!", sig)
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "params, key_size",
        [
            (
                {1: 4, 3: 4},  # HMAC 256/64
                32,
            ),
            (
                {1: 4, 3: 5},  # HMAC 256/256
                32,
            ),
            (
                {1: 4, 3: 6},  # HMAC 384/384
                48,
            ),
            (
                {1: 4, 3: 7},  # HMAC 512/512
                64,
            ),
        ],
    )
    def test_hmac_key_constructor_without_key(self, params, key_size):
        key = HMACKey(params)
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == params[3]
        assert len(key.key_ops) == 2
        assert 9 in key.key_ops
        assert 10 in key.key_ops
        assert key.base_iv is None
        assert len(key.key) == key_size
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
            (
                {1: 4, -1: b"mysecret", 3: 4, 4: [1, 2, 3]},
                "Unknown or not permissible key_ops(4) for MACAuthenticationKey: 1.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 4, 4: [9, 10, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_hmac_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            HMACKey(invalid)
            pytest.fail("HMACKey should fail.")
        assert msg in str(err.value)

    def test_hmac_key_sign_with_invalid_args(self):
        key = HMACKey(
            {
                1: 4,
                -1: b"mysecret",
                3: 5,  # HMAC 256/256
            }
        )
        with pytest.raises(EncodeError) as err:
            key.sign(123)
            pytest.fail("sign should fail.")
        assert "Failed to sign." in str(err.value)

    def test_hmac_key_verify_with_invalid_signature(self):
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
        assert len(key.key_ops) == 2
        assert 9 in key.key_ops
        assert 10 in key.key_ops
        assert key.base_iv is None
        sig = key.sign(b"Hello world!")
        with pytest.raises(VerifyError) as err:
            key.verify(b"Hello world!", sig + b"xxx")
            pytest.fail("verify should fail.")
        assert "Failed to compare digest." in str(err.value)


class TestAESCCMKey:
    """
    Tests for AESCCMKey.
    """

    def test_aesccm_key_constructor_with_aes_ccm_16_64_128(self):
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
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(13)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "key_args, nonce",
        [
            (
                {1: 4, 3: 10},
                token_bytes(13),
            ),
            (
                {1: 4, 3: 11},
                token_bytes(13),
            ),
            (
                {1: 4, 3: 12},
                token_bytes(7),
            ),
            (
                {1: 4, 3: 13},
                token_bytes(7),
            ),
            (
                {1: 4, 3: 30},
                token_bytes(13),
            ),
            (
                {1: 4, 3: 31},
                token_bytes(13),
            ),
            (
                {1: 4, 3: 32},
                token_bytes(7),
            ),
            (
                {1: 4, 3: 33},
                token_bytes(7),
            ),
        ],
    )
    def test_aesccm_key_constructor_with_aes_ccm_without_key(self, key_args, nonce):
        key = AESCCMKey(key_args)
        assert key.kty == 4
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
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
            (
                {1: 4, 3: 10, 4: [1, 2]},
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {1: 4, 3: 10, 4: [3, 4, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {1: 4, 3: 10, 4: [5, 6, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_aesccm_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            AESCCMKey(invalid)
            pytest.fail("AESCCMKey should fail.")
        assert msg in str(err.value)

    def test_aesgcm_key_encrypt_without_msg(self):
        key = AESCCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 10,  # AES-CCM-16-64-128
            }
        )
        nonce = token_bytes(13)
        with pytest.raises(EncodeError) as err:
            key.encrypt(None, nonce=nonce)
        assert "Failed to encrypt." in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_nonce(self):
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
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(13)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(13))
        assert "Failed to decrypt." in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_length_nonce(self):
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
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(13)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(ValueError) as err:
            key.decrypt(encrypted, nonce=token_bytes(7))
        assert "The length of nonce should be 13 bytes." in str(err.value)


class TestAESGCMKey:
    """
    Tests for AESGCMKey.
    """

    def test_aesgcm_key_constructor_with_aes_gcm_a128gcm(self):
        key = AESGCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 1,  # A128GCM
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 1
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(12)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "key_args",
        [
            {1: 4, 3: 1},
            {1: 4, 3: 2},
            {1: 4, 3: 3},
        ],
    )
    def test_aesgcm_key_constructor_with_aes_ccm_without_key(self, key_args):
        key = AESGCMKey(key_args)
        assert key.kty == 4
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(12)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 4, -1: b"mysecret", 3: 4},
                "Unsupported or unknown alg(3) for AES GCM: 4",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 1},
                "The length of A128GCM key should be 16 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 2},
                "The length of A192GCM key should be 24 bytes.",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 3},
                "The length of A256GCM key should be 32 bytes.",
            ),
            (
                {1: 4, 3: 1, 4: [1, 2]},
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {1: 4, 3: 1, 4: [3, 4, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {1: 4, 3: 1, 4: [5, 6, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_aesgcm_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            AESGCMKey(invalid)
            pytest.fail("AESGCMKey should fail.")
        assert msg in str(err.value)

    def test_aesgcm_key_encrypt_with_empty_nonce(self):
        key = AESGCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 1,  # A128GCM
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_aesgcm_key_decrypt_with_invalid_nonce(self):
        key = AESGCMKey(
            {
                1: 4,
                -1: token_bytes(16),
                3: 1,  # A128GCM
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 1
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(12)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(12))
        assert "Failed to decrypt." in str(err.value)


class TestChaCha20Key:
    """
    Tests for ChaCha20Key.
    """

    def test_chacha20_key_constructor(self):
        key = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        assert key.kty == 4
        assert key.kid is None
        assert key.alg == 24
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(12)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "key_args",
        [
            {1: 4, 3: 24},
        ],
    )
    def test_chacha20_key_constructor_without_key(self, key_args):
        key = ChaCha20Key(key_args)
        assert key.kty == 4
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert 3 in key.key_ops
        assert 4 in key.key_ops
        assert 5 in key.key_ops
        assert 6 in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(12)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 4, -1: b"mysecret", 3: 0},
                "Unsupported or unknown alg(3) for ChaCha20: 0",
            ),
            (
                {1: 4, -1: b"mysecret", 3: 24},
                "The length of ChaCha20/Poly1305 key should be 32 bytes.",
            ),
            (
                {1: 4, 3: 24, 4: [1, 2]},
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {1: 4, 3: 24, 4: [3, 4, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {1: 4, 3: 24, 4: [5, 6, 11]},
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_chacha20_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            ChaCha20Key(invalid)
            pytest.fail("ChaCha20Key should fail.")
        assert msg in str(err.value)

    def test_chacha20_key_encrypt_with_empty_nonce(self):
        key = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_chacha20_key_decrypt_with_different_nonce(self):
        key = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        nonce = token_bytes(12)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(12))
            pytest.fail("decrypt should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_chacha20_key_decrypt_with_different_key(self):
        key = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        key2 = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        nonce = token_bytes(12)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key2.decrypt(encrypted, nonce=nonce)
            pytest.fail("decrypt should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_chacha20_key_decrypt_with_invalid_nonce(self):
        key = ChaCha20Key(
            {
                1: 4,
                -1: token_bytes(32),
                3: 24,  # ChaCha20/Poly1305
            }
        )
        nonce = token_bytes(12)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(8))
            pytest.fail("decrypt should fail.")
        assert "Failed to decrypt." in str(err.value)
