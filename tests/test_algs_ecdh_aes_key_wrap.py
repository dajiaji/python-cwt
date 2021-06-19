"""
Tests for Direct.
"""
import pytest

from cwt.cose import COSE
from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError, EncodeError
from cwt.recipient import Recipient
from cwt.recipient_algs.ecdh_aes_key_wrap import ECDH_AESKeyWrap

from .utils import key_path


class TestECDH_AESKeyWrap:
    """
    Tests for ECDH_AESKeyWrap.
    """

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_es_a128kw(self):
        ctx = ECDH_AESKeyWrap({1: -29}, {4: b"01"})
        assert isinstance(ctx, ECDH_AESKeyWrap)
        assert ctx.alg == -29
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_es_a192kw(self):
        ctx = ECDH_AESKeyWrap({1: -30}, {4: b"01"})
        assert ctx.alg == -30
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_es_a256kw(self):
        ctx = ECDH_AESKeyWrap({1: -31}, {4: b"01"})
        assert ctx.alg == -31
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_ss_a128kw(self):
        ctx = ECDH_AESKeyWrap({1: -32}, {4: b"01"})
        assert ctx.alg == -32
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_ss_a192kw(self):
        ctx = ECDH_AESKeyWrap({1: -33}, {4: b"01"})
        assert ctx.alg == -33
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_constructor_with_ecdh_ss_a256kw(self):
        ctx = ECDH_AESKeyWrap({1: -34}, {4: b"01"})
        assert ctx.alg == -34
        assert ctx.kid == b"01"

    def test_ecdh_aes_key_wrap_decode_key_without_alg(self):
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = ECDH_AESKeyWrap({1: -29}, {4: b"01"})
        with pytest.raises(ValueError) as err:
            ctx.decode_key(key)
            pytest.fail("decode_key() should fail.")
        assert "alg should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            ECDH_AESKeyWrap({1: -1}, {4: b"01"})
            pytest.fail("ECDH_AESKeyWrap() should fail.")
        assert "Unknown alg(1) for ECDH with key wrap: -1." in str(err.value)

    def test_ecdh_aes_key_wrap_wrap_key_without_deriving_key(self):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        with pytest.raises(EncodeError) as err:
            rec.wrap_key(enc_key.key)
            pytest.fail("wrap_key should fail.")
        assert "Should call derive_key() before calling wrap_key()." in str(err.value)

    def test_ecdh_aes_key_wrap_wrap_key_with_invalid_arg(self):
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())
        rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        with pytest.raises(EncodeError) as err:
            rec.wrap_key(b"")
            pytest.fail("wrap_key should fail.")
        assert "Failed to wrap key." in str(err.value)

    def test_ecdh_aes_key_wrap_derive_key_without_kid(self):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())
        rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        rec.wrap_key(enc_key.key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-ES+A128KW")
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_aes_key_wrap_derive_key_without_cose_key(self):
        rec = Recipient.new(protected={1: -29})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
            pytest.fail("derive_key() should fail.")
        assert "Internal COSE key should be set for key derivation in advance." in str(
            err.value
        )

    def test_ecdh_aes_key_wrap_derive_key_without_public_key(self):
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"})
            pytest.fail("derive_key() should fail.")
        assert "public_key should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_derive_key_with_invalid_private_key(self):
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        rec.wrap_key(enc_key.key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        another_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+A128KW",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        with pytest.raises(DecodeError) as err:
            ctx.decode(encoded, another_priv_key, context={"alg": "A128GCM"})
            pytest.fail("decode() should fail.")
        assert "Failed to decode key." in str(err.value)

    def test_ecdh_aes_key_wrap_derive_key_with_invalid_key(self):
        cose_key = COSEKey.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"}
        )
        rec = Recipient.new(protected={"alg": "ECDH-ES+A128KW"}, cose_key=cose_key)
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"}, public_key=private_key)
            pytest.fail("derive_key() should fail.")
        assert "public_key should be elliptic curve public key." in str(err.value)
