"""
Tests for Direct.
"""

from secrets import token_bytes

import cbor2
import pytest

from cwt.cose import COSE
from cwt.cose_key import COSEKey
from cwt.exceptions import DecodeError
from cwt.recipient import Recipient
from cwt.recipient_algs.ecdh_direct_hkdf import ECDH_DirectHKDF

from .utils import key_path


@pytest.fixture(scope="session", autouse=True)
def sender_key_es():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "alg": "ECDH-ES+HKDF-256",
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
            "alg": "ECDH-ES+HKDF-256",
            "kid": "01",
            "crv": "P-256",
            "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
            "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
        }
    )


class TestECDH_DirectHKDF:
    """
    Tests for ECDH_DirectHKDF.
    """

    def test_ecdh_direct_hkdf_constructor_with_ecdh_es_256(self):
        ctx = Recipient.new({1: -25}, {4: b"01"}, context={"alg": "A128GCM"})
        assert isinstance(ctx, ECDH_DirectHKDF)
        assert ctx.alg == -25
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_es_512(self):
        ctx = Recipient.new({1: -26}, {4: b"01"}, context={"alg": "A128GCM"})
        assert ctx.alg == -26
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_ss_256(self):
        ctx = Recipient.new({1: -27}, {4: b"01"}, context={"alg": "A128GCM"})
        assert ctx.alg == -27
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_ecdh_ss_512(self):
        ctx = Recipient.new({1: -28}, {4: b"01"}, context={"alg": "A128GCM"})
        assert ctx.alg == -28
        assert ctx.kid == b"01"

    def test_ecdh_direct_hkdf_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -99}, {4: b"01"}, context={"alg": "A128GCM"})
            pytest.fail("ECDH_DirectHKDF() should fail.")
        assert "Unsupported or unknown alg(1): -99." in str(err.value)

    def test_ecdh_direct_hkdf_encode_with_ecdh_ss_p256(self):
        sender_priv_key = COSEKey.from_jwk(
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
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={
                "alg": "ECDH-SS+HKDF-256",
                "salt": token_bytes(64),
            },
            sender_key=sender_priv_key,
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-SS+HKDF-256")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_with_ecdh_ss_p521(self):
        sender_priv_key = COSEKey.from_jwk(
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
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={
                1: -28,  # "alg": "ECDH-SS+HKDF-512",
                -20: token_bytes(64),
            },
            sender_key=sender_priv_key,
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es512.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-SS+HKDF-512")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_with_raw_context(self):
        with open(key_path("public_key_es256.pem")) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context=[
                1,
                [None, None, None],
                [None, None, None],
                [128, cbor2.dumps({1: -25})],
            ],
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-ES+HKDF-256")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_with_ecdh_ss_p521_without_salt(self):
        sender_priv_key = COSEKey.from_jwk(
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
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={
                "alg": "ECDH-SS+HKDF-512",
            },
            sender_key=sender_priv_key,
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es512.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-SS+HKDF-512")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_with_ecdh_ss_p521_with_default_salt(self):
        sender_priv_key = COSEKey.from_jwk(
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
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={
                "alg": "ECDH-SS+HKDF-512",
                "salt": "aabbccddeeff",
            },
            sender_key=sender_priv_key,
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es512.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-SS+HKDF-512")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_without_salt(self):
        with open(key_path("public_key_es256.pem")) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context=[
                1,
                [None, None, None],
                [None, None, None],
                [128, cbor2.dumps({1: -25})],
            ],
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path("private_key_es256.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-ES+HKDF-256")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_encode_with_party_u_nonce(self):
        nonce = token_bytes(32)
        with open(key_path("public_key_es256.pem")) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        context = [
            1,
            [None, nonce, None],
            [None, None, None],
            [128, cbor2.dumps({1: -25})],
        ]
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context=context,
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])
        assert nonce == rec._unprotected[-22]
        with open(key_path("private_key_es256.pem")) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg="ECDH-ES+HKDF-256")
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context=context)

    def test_ecdh_direct_hkdf_encode_with_party_v_nonce(self):
        nonce = token_bytes(32)
        with open(key_path("public_key_es256.pem")) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context=[
                1,
                [None, None, None],
                [None, nonce, None],
                [128, cbor2.dumps({1: -25})],
            ],
        )
        _, enc_key = rec.encode()
        assert enc_key.alg == 1
        assert nonce == rec._unprotected[-25]

    def test_ecdh_direct_hkdf_encode_with_supp_pub_other(self):
        nonce = token_bytes(32)
        with open(key_path("public_key_es256.pem")) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context=[
                1,
                [None, None, None],
                [None, nonce, None],
                [128, cbor2.dumps({1: -25}), b"other"],
            ],
        )
        _, enc_key = rec.encode()
        assert enc_key.alg == 1
        assert nonce == rec._unprotected[-25]

    # def test_ecdh_direct_hkdf_encode_without_sender_key(self, recipient_public_key):
    #     sender = ECDH_DirectHKDF({1: -25}, {4: b"01"}, recipient_key=recipient_public_key, context={"alg": "A128GCM"})
    #     with pytest.raises(ValueError) as err:
    #         sender.encode()
    #         pytest.fail("encode() should fail.")
    #     assert "sender_key should be set in advance." in str(err.value)

    def test_ecdh_direct_hkdf_encode_without_recipient_key(self):
        sender = Recipient.new({1: -25}, {4: b"01"}, context={"alg": "A128GCM"})
        with pytest.raises(ValueError) as err:
            sender.encode()
            pytest.fail("encode() should fail.")
        assert "recipient_key should be set in advance." in str(err.value)

    def test_ecdh_direct_hkdf_encode_without_context(self, sender_key_es):
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -25}, {4: b"01"}, sender_key=sender_key_es)
            pytest.fail("Recipient.new() should fail.")
        assert "context should be set." in str(err.value)

    def test_ecdh_direct_hkdf_encode_with_invalid_recipient_key(self, sender_key_es, recipient_private_key):
        rec = Recipient.new(
            protected={"alg": "ECDH-ES+HKDF-256"},
            sender_key=sender_key_es,
            recipient_key=recipient_private_key,
            context={"alg": "A128GCM"},
        )
        with pytest.raises(ValueError) as err:
            rec.encode()
            pytest.fail("encode() should fail.")
        assert "public_key should be elliptic curve public key." in str(err.value)

    def test_ecdh_direct_hkdf_encode_and_extract_with_ecdh_es(self, sender_key_es, recipient_public_key, recipient_private_key):
        sender = Recipient.new(
            {1: -25}, {4: b"01"}, sender_key=sender_key_es, recipient_key=recipient_public_key, context={"alg": "A128GCM"}
        )
        encoded, enc_key = sender.encode()
        recipient = Recipient.from_list(encoded, context={"alg": "A128GCM"})
        decoded_key = recipient.decode(recipient_private_key, as_cose_key=True)
        assert enc_key.key == decoded_key.key

    @pytest.mark.parametrize(
        "alg, crv, private_key_path, public_key_path",
        [
            (-26, 3, "private_key_es512.pem", "public_key_es512.pem"),
            (-25, 1, "private_key_es256.pem", "public_key_es256.pem"),
        ],
    )
    def test_ecdh_direct_hkdf_through_cose_api_with_ecdh_es(self, alg, crv, private_key_path, public_key_path):
        # sender_key = COSEKey.new({1: 2, -1: crv, 3: alg})
        with open(key_path(public_key_path)) as key_file:
            pub_key = COSEKey.from_pem(key_file.read(), kid="01")
        rec = Recipient.new(unprotected={1: alg}, recipient_key=pub_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])

        with open(key_path(private_key_path)) as key_file:
            priv_key = COSEKey.from_pem(key_file.read(), kid="01", alg=alg)
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_through_cose_api(self, recipient_public_key, recipient_private_key):
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=recipient_public_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])
        assert b"Hello world!" == ctx.decode(encoded, recipient_private_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_through_cose_api_without_kid(self):
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "01",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])
        assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_ecdh_direct_hkdf_extract_with_invalid_private_key(self, recipient_public_key):
        rec = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=recipient_public_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", recipients=[rec])
        another_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
                "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
            }
        )
        with pytest.raises(DecodeError) as err:
            ctx.decode(encoded, another_priv_key, context={"alg": "A128GCM"})
            pytest.fail("decode() should fail.")
        assert "Failed to decrypt." in str(err.value)
