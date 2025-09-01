# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import cbor2
import pytest

from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, DecodeError, EncodeError


class TestCOSE_HPKE:
    """
    Tests for COSE-HPKE.
    """

    @pytest.mark.parametrize(
        "alg",
        [
            COSEAlgs.HPKE_0,
        ],
    )
    def test_cose_hpke_kem_0x0010(self, alg):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: alg,
            },
            unprotected={
                COSEHeaders.KID: b"01",  # kid: "01"
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    def test_cose_hpke_encrypt0_missing_ek_raises(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
            unprotected={COSEHeaders.KID: b"01"},
        )

        # Tamper encoded message: remove ek(-4)
        tag = cbor2.loads(encoded)
        assert tag.tag == 16
        p, u, c = tag.value
        u2 = {k: v for k, v in u.items() if k != -4}
        tampered = cbor2.CBORTag(16, [p, u2, c])
        tampered_bytes = cbor2.dumps(tampered)

        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        with pytest.raises(DecodeError) as err:
            recipient.decode(tampered_bytes, rsk)
        assert "ek (-4) is required for HPKE." in str(err.value)

    def test_cose_hpke_encrypt0_ek_wrong_type_raises(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
            unprotected={COSEHeaders.KID: b"01"},
        )

        # Tamper ek type to int
        tag = cbor2.loads(encoded)
        assert tag.tag == 16
        p, u, c = tag.value
        u[-4] = 123  # wrong type
        tampered = cbor2.CBORTag(16, [p, u, c])
        tampered_bytes = cbor2.dumps(tampered)

        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        with pytest.raises(DecodeError) as err:
            recipient.decode(tampered_bytes, rsk)
        assert "ek (-4) must be bstr." in str(err.value)

    def test_cose_hpke_encode_ek_wrong_type_header_validation(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                rpk,
                protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
                unprotected={COSEHeaders.KID: b"01", "ek": 123},
            )
        assert "ek (-4) must be bstr." in str(err.value)

    def test_cose_hpke_encrypt0_psk_id_wrong_type_header_validation(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                rpk,
                protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
                unprotected={COSEHeaders.KID: b"01", COSEHeaders.PSK_ID: 123},
            )
        assert "psk_id (-5) must be bstr." in str(err.value)

    def test_cose_hpke_encrypt0_with_psk_id_roundtrip(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
            unprotected={COSEHeaders.KID: b"01", COSEHeaders.PSK_ID: b"psk-01"},
            hpke_psk=b"secret-psk",
        )

        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk, hpke_psk=b"secret-psk")

    @pytest.mark.parametrize(
        "alg",
        [COSEAlgs.HPKE_1],
    )
    def test_cose_hpke_kem_0x0011(self, alg):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-384",
                "x": "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
                "y": "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: alg,
            },
            unprotected={
                COSEHeaders.KID: b"01",  # kid: "01"
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-384",
                "x": "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
                "y": "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
                "d": "1pImEKbrr771-RKi8Tb7tou_WjiR7kwui_nMu16449rk3lzAqf9buUhTkJ-pogkb",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    def test_cose_hpke_encrypt0_psk_id_without_psk_should_error_on_encode(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        with pytest.raises(EncodeError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                rpk,
                protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
                unprotected={COSEHeaders.KID: b"01", COSEHeaders.PSK_ID: b"psk-01"},
            )
        assert "hpke_psk is required when psk_id (-5) is provided." in str(err.value)

    def test_cose_hpke_encrypt0_psk_id_without_psk_should_error_on_decode(self):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        sender = COSE.new()
        # First, produce a base-mode (no psk_id) and then inject psk_id to simulate peer mismatch
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
            unprotected={COSEHeaders.KID: b"01"},
        )
        tag = cbor2.loads(encoded)
        p, u, c = tag.value
        u[-5] = b"psk-01"
        tampered = cbor2.dumps(cbor2.CBORTag(16, [p, u, c]))

        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        with pytest.raises(DecodeError) as err:
            recipient.decode(tampered, rsk)
        assert "hpke_psk is required when psk_id (-5) is provided." in str(err.value)

    @pytest.mark.parametrize(
        "alg",
        [COSEAlgs.HPKE_2],
    )
    def test_cose_hpke_kem_0x0012(self, alg):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-521",
                "kid": "01",
                "x": "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
                "y": "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: alg,
            },
            unprotected={
                COSEHeaders.KID: b"01",  # kid: "01"
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-521",
                "kid": "01",
                "x": "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
                "y": "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
                "d": "ADYyo73ZKicOjwGDYQ_ybZKnVzdAcxGm9OVAxQjzgVM4jaS-Iwtkz90oLdDz3shgKlDgtRK2Aa9lMhqR94hBo4IE",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    @pytest.mark.parametrize(
        "alg",
        [COSEAlgs.HPKE_3, COSEAlgs.HPKE_4],
    )
    def test_cose_hpke_kem_0x0020(self, alg):
        rpk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "01",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "key_ops": [],
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: alg,
            },
            unprotected={
                COSEHeaders.KID: b"01",  # kid: "01"
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "01",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
                "key_ops": ["deriveBits"],
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    @pytest.mark.parametrize(
        "alg",
        [COSEAlgs.HPKE_5, COSEAlgs.HPKE_6],
    )
    def test_cose_hpke_kem_0x0021(self, alg):
        rpk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X448",
                "kid": "01",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: alg,
            },
            unprotected={
                COSEHeaders.KID: b"01",  # kid: "01"
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X448",
                "kid": "01",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
                "d": "rJJRG3nshyCtd9CgXld8aNaB9YXKR0UOi7zj7hApg9YH4XdBO0G8NcAFNz_uPH2GnCZVcSDgV5c",
                "key_ops": ["deriveBits"],
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)
