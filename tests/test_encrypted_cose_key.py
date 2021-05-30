from secrets import token_bytes

import cbor2
import pytest

from cwt import COSEKey, EncryptedCOSEKey


class TestEncryptedCOSEKey:
    """
    Tests for EncryptedCOSEKey.
    """

    def test_encrypted_cose_key_from_cose_key_with_nonce(self):
        nonce = token_bytes(12)
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        pop_key = COSEKey.from_symmetric_key(alg="HMAC 256/256")
        res = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, nonce=nonce)
        assert isinstance(res, list)
        assert len(res) == 3
        protected = cbor2.loads(res[0])
        assert protected[1] == 24
        assert isinstance(res[1], dict)
        assert isinstance(res[1][5], bytes) and res[1][5] == nonce

    def test_encrypted_cose_key_from_cose_key_with_invalid_encryption_key(self):
        enc_key = COSEKey.from_symmetric_key(alg="HMAC 256/64")
        pop_key = COSEKey.from_symmetric_key(alg="HMAC 256/256")
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.from_cose_key(pop_key, enc_key)
            pytest.fail("to_ should fail.")
        assert (
            "Nonce generation is not supported for the key. Set a nonce explicitly."
            in str(err.value)
        )
