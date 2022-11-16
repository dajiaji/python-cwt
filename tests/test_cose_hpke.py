# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import pytest

from cwt import COSE, COSEKey


class TestCOSE_HPKE:
    """
    Tests for COSE-HPKE.
    """

    @pytest.mark.parametrize(
        "kdf, aead",
        [
            (0x0001, 0x0001),
            (0x0001, 0x0002),
            (0x0001, 0x0003),
            (0x0002, 0x0001),
            (0x0002, 0x0002),
            (0x0002, 0x0003),
            (0x0003, 0x0001),
            (0x0003, 0x0002),
            (0x0003, 0x0003),
        ],
    )
    def test_cose_hpke_kem_0x0010(self, kdf, aead):
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
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0010,
                    2: kdf,
                    3: aead,
                },
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

    @pytest.mark.parametrize(
        "kdf, aead",
        [
            (0x0001, 0x0001),
            (0x0001, 0x0002),
            (0x0001, 0x0003),
            (0x0002, 0x0001),
            (0x0002, 0x0002),
            (0x0002, 0x0003),
            (0x0003, 0x0001),
            (0x0003, 0x0002),
            (0x0003, 0x0003),
        ],
    )
    def test_cose_hpke_kem_0x0011(self, kdf, aead):
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
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0011,
                    2: kdf,
                    3: aead,
                },
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

    @pytest.mark.parametrize(
        "kdf, aead",
        [
            (0x0001, 0x0001),
            (0x0001, 0x0002),
            (0x0001, 0x0003),
            (0x0002, 0x0001),
            (0x0002, 0x0002),
            (0x0002, 0x0003),
            (0x0003, 0x0001),
            (0x0003, 0x0002),
            (0x0003, 0x0003),
        ],
    )
    def test_cose_hpke_kem_0x0012(self, kdf, aead):
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "use": "sig",
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
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0012,
                    2: kdf,
                    3: aead,
                },
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "use": "sig",
                "crv": "P-521",
                "kid": "01",
                "x": "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
                "y": "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
                "d": "ADYyo73ZKicOjwGDYQ_ybZKnVzdAcxGm9OVAxQjzgVM4jaS-Iwtkz90oLdDz3shgKlDgtRK2Aa9lMhqR94hBo4IE",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)
