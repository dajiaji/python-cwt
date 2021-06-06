"""
Tests for Direct.
"""
import cbor2
import pytest

from cwt.cose import COSE
from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError
from cwt.recipient import Recipient
from cwt.recipient_algs.ecdh_direct_hkdf import ECDH_DirectHKDF

from .utils import key_path


class TestECDH_DirectHKDF:
    """
    Tests for ECDH_DirectHKDF.
    """

    def test_ecdh_direct_hkdf_constructor_with_ecdh_es_256(self):
        ctx = ECDH_DirectHKDF({1: -25}, {4: b"01"})
        assert isinstance(ctx, ECDH_DirectHKDF)
        assert ctx.alg == -25
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_es_512(self):
        ctx = ECDH_DirectHKDF({1: -26}, {4: b"01"})
        assert ctx.alg == -26
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_ss_256(self):
        ctx = ECDH_DirectHKDF({1: -27}, {4: b"01"})
        assert ctx.alg == -27
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_ss_512(self):
        ctx = ECDH_DirectHKDF({1: -28}, {4: b"01"})
        assert ctx.alg == -28
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            ECDH_DirectHKDF({1: -1}, {4: b"01"})
            pytest.fail("ECDH_DirectHKDF() should fail.")
        assert "Unknown alg(1) for ECDH with HKDF: -1." in str(err.value)

    @pytest.mark.parametrize(
        "alg, private_key_path, public_key_path",
        [
            (-28, "private_key_es512.pem", "public_key_es512.pem"),
            (-27, "private_key_es256.pem", "public_key_es256.pem"),
            (-26, "private_key_es512.pem", "public_key_es512.pem"),
            (-25, "private_key_es256.pem", "public_key_es256.pem"),
        ],
    )
    def test_ecdh_direct_hkdf_derive_key(self, alg, private_key_path, public_key_path):
        rec = Recipient.new(protected={1: alg})
        with open(key_path(private_key_path)) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path(public_key_path)) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_with_raw_context(self):
        rec = Recipient.from_json({"alg": "ECDH-ES+HKDF-256"})
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key(
            [1, [None, None, None], [None, None, None], [128, cbor2.dumps({1: -25})]],
            public_key=public_key,
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_without_kid(self):
        rec = Recipient.from_json({"alg": "ECDH-ES+HKDF-256"})
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_with_invalid_private_key(self):
        rec = Recipient.from_json({"alg": "ECDH-ES+HKDF-256"})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        another_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
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
        assert "Failed to decrypt." in str(err.value)

    def test_ecdh_direct_hkdf_derive_key_with_invalid_key(self):
        rec = Recipient.new(protected={"alg": "ECDH-ES+HKDF-256"})
        with open(key_path("private_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
            pytest.fail("derive_key() should fail.")
        assert "public_key should be EC public key." in str(err.value)
