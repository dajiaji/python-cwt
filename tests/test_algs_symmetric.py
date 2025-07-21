"""
Tests for SymmetricKey.
"""

from secrets import token_bytes

import pytest

from cwt.algs.symmetric import (
    AESCBCKey,
    AESCCMKey,
    AESCTRKey,
    AESGCMKey,
    ChaCha20Key,
    HMACKey,
    SymmetricKey,
)
from cwt.enums import COSEAlgs, COSEKeyOps, COSEKeyParams, COSEKeyTypes
from cwt.exceptions import DecodeError, EncodeError, VerifyError


class TestSymmetricKey:
    """
    Tests for SymmetricKey.
    """

    def test_symmetric_key_constructor_with_hmac_256_256(self):
        key = SymmetricKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
                COSEKeyParams.ALG: COSEAlgs.HS256,  # HMAC 256/256
            }
        )
        assert key.key == b"mysecret"
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.HS256
        assert key.key_ops == []
        assert key.base_iv is None

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {COSEKeyParams.KTY: COSEKeyTypes.EC2},
                "kty(1) should be Symmetric(4).",
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret"},
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
                COSEKeyParams.ALG: COSEAlgs.HS256,  # HMAC 256/256
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.HS256
        assert len(key.key_ops) == 2
        assert COSEKeyOps.MAC_CREATE in key.key_ops
        assert COSEKeyOps.MAC_VERIFY in key.key_ops
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.HS256_64},  # HMAC 256/64
                32,
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.HS256},  # HMAC 256/256
                32,
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.HS384},  # HMAC 384/384
                48,
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.HS512},  # HMAC 512/512
                64,
            ),
        ],
    )
    def test_hmac_key_constructor_without_key(self, params, key_size):
        key = HMACKey(params)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == params[COSEKeyParams.ALG]
        assert len(key.key_ops) == 2
        assert COSEKeyOps.MAC_CREATE in key.key_ops
        assert COSEKeyOps.MAC_VERIFY in key.key_ops
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
                {COSEKeyParams.KTY: COSEKeyTypes.EC2},
                "kty(1) should be Symmetric(4).",
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret"},
                "alg(3) not found.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A256GCM},
                "Unsupported or unknown alg(3) for HMAC.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEKeyOps.DERIVE_BITS,
                },
                "Unsupported or unknown alg(8) for HMAC.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.HS256_64,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY, COSEKeyOps.ENCRYPT],
                },
                "Unknown or not permissible key_ops(4) for MACAuthenticationKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.HS256_64,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.MAC_CREATE, COSEKeyOps.MAC_VERIFY, 11],
                },
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
                COSEKeyParams.ALG: COSEAlgs.HS256,  # HMAC 256/256
            }
        )
        with pytest.raises(EncodeError) as err:
            key.sign(123)
            pytest.fail("sign should fail.")
        assert "Failed to sign." in str(err.value)

    def test_hmac_key_verify_with_invalid_signature(self):
        key = HMACKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
                COSEKeyParams.ALG: COSEAlgs.HS256,  # HMAC 256/256
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.HS256
        assert len(key.key_ops) == 2
        assert COSEKeyOps.MAC_CREATE in key.key_ops
        assert COSEKeyOps.MAC_VERIFY in key.key_ops
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.AES_CCM_16_64_128
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128},
                token_bytes(13),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_256},
                token_bytes(13),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_64_128},
                token_bytes(7),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_64_256},
                token_bytes(7),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_128_128},
                token_bytes(13),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_128_256},
                token_bytes(13),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_128_128},
                token_bytes(7),
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_128_256},
                token_bytes(7),
            ),
        ],
    )
    def test_aesccm_key_constructor_with_aes_ccm_without_key(self, key_args, nonce):
        key = AESCCMKey(key_args)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                {COSEKeyParams.KTY: COSEKeyTypes.EC2},
                "kty(1) should be Symmetric(4).",
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: 123},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: {}},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: []},
                "k(-1) should be bytes(bstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret"},
                "alg(3) not found.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: 9},
                "Unsupported or unknown alg(9) for AES CCM.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: 34},
                "Unsupported or unknown alg(34) for AES CCM.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,
                },
                "The length of AES-CCM-16-64-128 key should be 16 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_256,
                },
                "The length of AES-CCM-16-64-256 key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_64_128,
                },
                "The length of AES-CCM-64-64-128 key should be 16 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_64_256,
                },
                "The length of AES-CCM-64-64-256 key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_128_128,
                },
                "The length of AES-CCM-16-128-128 key should be 16 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_128_256,
                },
                "The length of AES-CCM-16-128-256 key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_128_128,
                },
                "The length of AES-CCM-64-128-128 key should be 16 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_64_128_256,
                },
                "The length of AES-CCM-64-128-256 key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                },
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.ENCRYPT, COSEKeyOps.DECRYPT, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.WRAP_KEY, COSEKeyOps.UNWRAP_KEY, 11],
                },
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,  # AES-CCM-16-64-128
            }
        )
        nonce = token_bytes(13)
        with pytest.raises(EncodeError) as err:
            key.encrypt(None, nonce=nonce)
        assert "Failed to encrypt." in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_nonce(self):
        key = AESCCMKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.AES_CCM_16_64_128
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(13)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(13))
        assert "Failed to decrypt." in str(err.value)

    def test_aesccm_key_decrypt_with_invalid_length_nonce(self):
        key = AESCCMKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.AES_CCM_16_64_128,  # AES-CCM-16-64-128
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.AES_CCM_16_64_128
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128GCM,  # A128GCM
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128GCM
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128GCM},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A192GCM},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A256GCM},
        ],
    )
    def test_aesgcm_key_constructor_with_aes_ccm_without_key(self, key_args):
        key = AESGCMKey(key_args)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.HS256_64,
                },
                "Unsupported or unknown alg(3) for AES GCM: 4",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A128GCM},
                "The length of A128GCM key should be 16 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A192GCM},
                "The length of A192GCM key should be 24 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A256GCM},
                "The length of A256GCM key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128GCM,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                },
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128GCM,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.ENCRYPT, COSEKeyOps.DECRYPT, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128GCM,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.WRAP_KEY, COSEKeyOps.UNWRAP_KEY, 11],
                },
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128GCM,  # A128GCM
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_aesgcm_key_decrypt_with_invalid_nonce(self):
        key = AESGCMKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128GCM,  # A128GCM
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128GCM
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.CHACHA20_POLY1305
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305},
        ],
    )
    def test_chacha20_key_constructor_without_key(self, key_args):
        key = ChaCha20Key(key_args)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
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
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: 0},
                "Unsupported or unknown alg(3) for ChaCha20: 0",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,
                },
                "The length of ChaCha20/Poly1305 key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                },
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.ENCRYPT, COSEKeyOps.DECRYPT, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.WRAP_KEY, COSEKeyOps.UNWRAP_KEY, 11],
                },
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_chacha20_key_decrypt_with_different_nonce(self):
        key = ChaCha20Key(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
            }
        )
        key2 = ChaCha20Key(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(32),
                COSEKeyParams.ALG: COSEAlgs.CHACHA20_POLY1305,  # ChaCha20/Poly1305
            }
        )
        nonce = token_bytes(12)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        with pytest.raises(DecodeError) as err:
            key.decrypt(encrypted, nonce=token_bytes(8))
            pytest.fail("decrypt should fail.")
        assert "Failed to decrypt." in str(err.value)


class TestAESCTRKey:
    """
    Tests for AESCTRKey.
    """

    def test_aesctr_key_constructor_with_aes_ctr_a128ctr(self):
        key = AESCTRKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CTR,  # A128CTR
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128CTR
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "key_args",
        [
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128CTR},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A192CTR},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A256CTR},
        ],
    )
    def test_aesctr_key_constructor_with_aes_ctr_without_key(self, key_args):
        key = AESCTRKey(key_args)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.HS256_64,
                },
                "Unsupported or unknown alg(3) for AES CTR: 4",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A128CTR},
                "The length of A128CTR key should be 16 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A192CTR},
                "The length of A192CTR key should be 24 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A256CTR},
                "The length of A256CTR key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CTR,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                },
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CTR,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.ENCRYPT, COSEKeyOps.DECRYPT, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CTR,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.WRAP_KEY, COSEKeyOps.UNWRAP_KEY, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_aesctr_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            AESCTRKey(invalid)
            pytest.fail("AESCTRKey should fail.")
        assert msg in str(err.value)

    def test_aesgcm_key_encrypt_with_empty_nonce(self):
        key = AESCTRKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CTR,  # A128CTR
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_aesctr_key_decrypt_with_invalid_nonce(self):
        key = AESCTRKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CTR,  # A128CTR
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128CTR
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        # alternate the nonce by incrementing the last byte
        invalid_nonce = nonce[0:-1] + ((nonce[-1] + 1) % 256).to_bytes(1, "big")
        assert nonce != invalid_nonce
        decrypted = key.decrypt(encrypted, nonce=invalid_nonce)
        assert encrypted != decrypted
        # as AES-CTR is non-AEAD cipher, integrity and authenticity is not guaranteed


class TestAESCBCKey:
    """
    Tests for AESCBCKey.
    """

    def test_aescbc_key_constructor_with_aes_cbc_a128cbc(self):
        key = AESCBCKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CBC,  # A128CBC
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128CBC
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    def test_aescbc_padding_with_aes_cbc_a128cbc(self):
        key = AESCBCKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CBC,  # A128CBC
            }
        )
        nonce = token_bytes(16)

        try:
            # if len(msg) is multiple of block size 16,
            # it would be the padding value (like b'\x16') and its length
            encrypted = key.encrypt(b"t" * 16, nonce=nonce)
            decrypted_raw = key._cipher.decrypt(data=encrypted, nonce=nonce)
            assert decrypted_raw[-16:] == (16).to_bytes(1, "big") * 16

            # otherwise, the remaining length = 16 - len(data) % 16
            # would be the padding value and its length
            for i in range(1, 16):
                encrypted = key.encrypt(b"t" * (16 + (16 - i)), nonce=nonce)
                decrypted_raw = key._cipher.decrypt(data=encrypted, nonce=nonce)
                assert decrypted_raw[-i:] == (i).to_bytes(1, "big") * i
        except Exception:
            pytest.fail("padding check should not fail.")

    @pytest.mark.parametrize(
        "key_args",
        [
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128CBC},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A192CBC},
            {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A256CBC},
        ],
    )
    def test_aescbc_key_constructor_with_aes_cbc_without_key(self, key_args):
        key = AESCBCKey(key_args)
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        try:
            encrypted = key.encrypt(b"Hello world!", nonce=nonce)
            assert key.decrypt(encrypted, nonce) == b"Hello world!"
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.K: b"mysecret",
                    COSEKeyParams.ALG: COSEAlgs.HS256_64,
                },
                "Unsupported or unknown alg(3) for AES CBC: 4",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A128CBC},
                "The length of A128CBC key should be 16 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A192CBC},
                "The length of A192CBC key should be 24 bytes.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: b"mysecret", COSEKeyParams.ALG: COSEAlgs.A256CBC},
                "The length of A256CBC key should be 32 bytes.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CBC,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                },
                "Unknown or not permissible key_ops(4) for ContentEncryptionKey: 1.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CBC,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.ENCRYPT, COSEKeyOps.DECRYPT, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128CBC,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.WRAP_KEY, COSEKeyOps.UNWRAP_KEY, 11],
                },
                "key_ops(4) includes invalid value: 11.",
            ),
        ],
    )
    def test_aescbc_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            AESCBCKey(invalid)
            pytest.fail("AESCBCKey should fail.")
        assert msg in str(err.value)

    def test_aesgcm_key_encrypt_with_empty_nonce(self):
        key = AESCBCKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CBC,  # A128CBC
            }
        )
        with pytest.raises(EncodeError) as err:
            key.encrypt(b"Hello world!", nonce=b"")
        assert "Failed to encrypt." in str(err.value)

    def test_aescbc_key_decrypt_with_invalid_nonce(self):
        key = AESCBCKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: token_bytes(16),
                COSEKeyParams.ALG: COSEAlgs.A128CBC,  # A128CBC
            }
        )
        assert key.kty == COSEKeyTypes.ASYMMETRIC
        assert key.kid is None
        assert key.alg == COSEAlgs.A128CBC
        assert len(key.key_ops) == 4
        assert COSEKeyOps.ENCRYPT in key.key_ops
        assert COSEKeyOps.DECRYPT in key.key_ops
        assert COSEKeyOps.WRAP_KEY in key.key_ops
        assert COSEKeyOps.UNWRAP_KEY in key.key_ops
        assert key.base_iv is None
        nonce = token_bytes(16)
        encrypted = key.encrypt(b"Hello world!", nonce=nonce)
        # alternate the nonce by incrementing the last byte
        invalid_nonce = nonce[0:-1] + ((nonce[-1] + 1) % 256).to_bytes(1, "big")
        assert nonce != invalid_nonce
        decrypted = key.decrypt(encrypted, nonce=invalid_nonce)
        assert encrypted != decrypted
        # as AES-CBC is non-AEAD cipher, integrity and authenticity is not guaranteed
