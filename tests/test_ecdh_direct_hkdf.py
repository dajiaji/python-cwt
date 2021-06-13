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
        "alg, crv, private_key_path, public_key_path",
        [
            (-26, 3, "private_key_es512.pem", "public_key_es512.pem"),
            (-25, 1, "private_key_es256.pem", "public_key_es256.pem"),
        ],
    )
    def test_ecdh_direct_hkdf_derive_key_with_ecdh_es(
        self, alg, crv, private_key_path, public_key_path
    ):
        cose_key = COSEKey.new({1: 2, -1: crv, 3: alg})
        rec = Recipient.new(protected={1: alg}, cose_key=cose_key)
        with open(key_path(public_key_path)) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path(private_key_path)) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01", alg=alg)
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_with_ecdh_es_p256(self):
        rec = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-SS+HKDF-256",
                "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
                "crv": "P-256",
                "kid": "01",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(
                key_file.read(), kid="01", alg="ECDH-SS+HKDF-256"
            )
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_with_ecdh_es_p521(self):
        rec = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-SS+HKDF-512",
                "d": "ADYyo73ZKicOjwGDYQ_ybZKnVzdAcxGm9OVAxQjzgVM4jaS-Iwtkz90oLdDz3shgKlDgtRK2Aa9lMhqR94hBo4IE",
                "crv": "P-521",
                "kid": "01",
                "x": "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
                "y": "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
            }
        )
        with open(key_path("public_key_es512.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path("private_key_es512.pem")) as key_file:
            private_key = COSEKey.from_pem(
                key_file.read(), kid="01", alg="ECDH-SS+HKDF-512"
            )
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_with_raw_context(self):
        rec = Recipient.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"}
        )
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key(
            [1, [None, None, None], [None, None, None], [128, cbor2.dumps({1: -25})]],
            public_key=public_key,
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(
                key_file.read(), kid="01", alg="ECDH-ES+HKDF-256"
            )
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_without_kid(self):
        rec = Recipient.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"}
        )
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-ES+HKDF-256")
        assert b"Hello world!" == ctx.decode(
            encoded, private_key, context={"alg": "A128GCM"}
        )

    def test_ecdh_direct_hkdf_derive_key_without_cose_key(self):
        rec = Recipient.new(protected={1: -25})
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
            pytest.fail("derive_key() should fail.")
        assert "Internal COSE key should be set for key derivation in advance." in str(
            err.value
        )

    def test_ecdh_direct_hkdf_derive_key_without_public_key(self):
        rec = Recipient.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"}
        )
        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"})
            pytest.fail("derive_key() should fail.")
        assert "public_key should be set." in str(err.value)

    def test_ecdh_direct_hkdf_derive_key_with_invalid_private_key(self):
        rec = Recipient.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"}
        )
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, recipients=[rec])
        another_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
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
        cose_key = COSEKey.from_jwk(
            {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"}
        )
        rec = Recipient.new(protected={"alg": "ECDH-ES+HKDF-256"}, cose_key=cose_key)
        with open(key_path("private_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        with pytest.raises(ValueError) as err:
            rec.derive_key({"alg": "A128GCM"}, public_key=public_key)
            pytest.fail("derive_key() should fail.")
        assert "public_key should be elliptic curve public key." in str(err.value)
