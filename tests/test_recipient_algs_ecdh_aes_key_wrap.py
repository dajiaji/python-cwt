"""
Tests for Direct.
"""
import pytest

from cwt.cose import COSE
from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError, EncodeError
from cwt.recipient import Recipient
from cwt.recipient_algs.ecdh_aes_key_wrap import ECDH_AESKeyWrap


@pytest.fixture(scope="session", autouse=True)
def sender_key_es():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "alg": "ECDH-ES+A128KW",
            "crv": "P-256",
        }
    )


@pytest.fixture(scope="session", autouse=True)
def recipient_public_key():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "01",
            "crv": "P-256",
            "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
            "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        }
    )


@pytest.fixture(scope="session", autouse=True)
def recipient_private_key():
    return COSEKey.from_jwk(
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

    def test_ecdh_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            ECDH_AESKeyWrap({1: -1}, {4: b"01"})
            pytest.fail("ECDH_AESKeyWrap() should fail.")
        assert "Unknown alg(1) for ECDH with key wrap: -1." in str(err.value)

    def test_ecdh_aes_key_wrap_encode_and_extract_with_ecdh_es(
        self, sender_key_es, recipient_public_key, recipient_private_key
    ):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        sender = ECDH_AESKeyWrap({1: -29}, {4: b"01"}, sender_key=sender_key_es)
        sender.apply(enc_key, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
        assert sender.ciphertext is not None

        encoded = sender.to_list()
        recipient = Recipient.from_list(encoded)
        decoded_key = recipient.extract(recipient_private_key, alg="ChaCha20/Poly1305", context={"alg": "A128GCM"})
        assert enc_key.key == decoded_key.key

    def test_ecdh_aes_key_wrap_through_cose_api(self, recipient_public_key, recipient_private_key):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        rec.apply(enc_key, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        assert b"Hello world!" == ctx.decode(encoded, recipient_private_key, context={"alg": "A128GCM"})

    def test_ecdh_aes_key_wrap_through_cose_api_without_kid(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        rec.apply(enc_key, recipient_key=pub_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "01",
                "alg": "ECDH-ES+A128KW",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_aes_key_wrap_apply_without_key(self, sender_key_es):
        sender = ECDH_AESKeyWrap({1: -29}, {4: b"01"}, sender_key=sender_key_es)
        with pytest.raises(ValueError) as err:
            sender.apply(recipient_key=recipient_public_key, context={"alg": "A128GCM"})
            pytest.fail("apply() should fail.")
        assert "key should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_apply_without_sender_key(self, recipient_public_key):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        sender = ECDH_AESKeyWrap({1: -29}, {4: b"01"})
        with pytest.raises(ValueError) as err:
            sender.apply(enc_key, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
            pytest.fail("apply() should fail.")
        assert "sender_key should be set in advance." in str(err.value)

    def test_ecdh_aes_key_wrap_apply_without_recipient_key(self, sender_key_es):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        sender = ECDH_AESKeyWrap({1: -29}, {4: b"01"}, sender_key=sender_key_es)
        with pytest.raises(ValueError) as err:
            sender.apply(enc_key, context={"alg": "A128GCM"})
            pytest.fail("apply() should fail.")
        assert "recipient_key should be set in advance." in str(err.value)

    def test_ecdh_aes_key_wrap_apply_without_context(self, sender_key_es):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        sender = ECDH_AESKeyWrap({1: -29}, {4: b"01"}, sender_key=sender_key_es)
        with pytest.raises(ValueError) as err:
            sender.apply(enc_key, recipient_key=recipient_public_key)
            pytest.fail("apply() should fail.")
        assert "context should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_apply_with_invalid_recipient_key(self, sender_key_es, recipient_private_key):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        rec = Recipient.new(protected={"alg": "ECDH-ES+A128KW"}, sender_key=sender_key_es)
        with pytest.raises(ValueError) as err:
            rec.apply(enc_key, recipient_key=recipient_private_key, context={"alg": "A128GCM"})
            pytest.fail("apply() should fail.")
        assert "public_key should be elliptic curve public key." in str(err.value)

    def test_ecdh_aes_key_wrap_apply_with_invalid_key_to_wrap(self, sender_key_es, recipient_public_key):
        mac_key = COSEKey.from_symmetric_key(key="xxx", alg="HS256")
        rec = Recipient.new(protected={"alg": "ECDH-ES+A128KW"}, sender_key=sender_key_es)
        with pytest.raises(EncodeError) as err:
            rec.apply(mac_key, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
            pytest.fail("apply() should fail.")
        assert "Failed to wrap key." in str(err.value)

    def test_ecdh_aes_key_wrap_extract_without_alg(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        ctx = ECDH_AESKeyWrap({1: -29}, {4: b"01"})
        with pytest.raises(ValueError) as err:
            ctx.extract(enc_key)
            pytest.fail("extract() should fail.")
        assert "alg should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_extract_without_context(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        ctx = ECDH_AESKeyWrap({1: -29}, {4: b"01"})
        with pytest.raises(ValueError) as err:
            ctx.extract(enc_key, alg="ChaCha20/Poly1305")
            pytest.fail("extract() should fail.")
        assert "context should be set." in str(err.value)

    def test_ecdh_aes_key_wrap_extract_with_invalid_recipient_private_key(self, recipient_public_key):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        rec = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        rec.apply(enc_key, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        recipient_private_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                # "alg": "ECDH-ES+A128KW",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        with pytest.raises(DecodeError) as err:
            ctx.decode(encoded, recipient_private_key, context={"alg": "A128GCM"})
            pytest.fail("extract() should fail.")
        assert "Failed to decode key." in str(err.value)
