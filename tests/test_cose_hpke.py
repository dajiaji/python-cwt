# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cwt import COSE, COSEKey
from cwt.algs.ec2 import EC2Key


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
                -4: [  # HPKE sender information
                    0x0010,
                    kdf,
                    aead,
                ],
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
                -4: [  # HPKE sender information
                    0x0011,
                    kdf,
                    aead,
                ],
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
                -4: [  # HPKE sender information
                    0x0012,
                    kdf,
                    aead,
                ],
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
    def test_cose_hpke_kem_0x0020(self, kdf, aead):
        rpk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "01",
                "alg": "HPKE",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "key_ops": ["deriveKey", "deriveBits"],
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
                -4: [  # HPKE sender information
                    0x0020,
                    kdf,
                    aead,
                ],
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "01",
                "alg": "HPKE",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
                "key_ops": ["deriveKey", "deriveBits"],
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
    def test_cose_hpke_kem_0x0021(self, kdf, aead):
        rpk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X448",
                "kid": "01",
                "alg": "HPKE",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
                "key_ops": ["deriveKey"],
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
                -4: [  # HPKE sender information
                    0x0021,
                    kdf,
                    aead,
                ],
            },
        )

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "crv": "X448",
                "kid": "01",
                "alg": "HPKE",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
                "d": "rJJRG3nshyCtd9CgXld8aNaB9YXKR0UOi7zj7hApg9YH4XdBO0G8NcAFNz_uPH2GnCZVcSDgV5c",
                "key_ops": ["deriveKey"],
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    def test_cose_hpke_with_t_cose_example(self):
        # t_cose/examples/keys/init_keys_psa.c:fixed_test_p256r1_public_key
        pkr_buf = bytes(
            bytearray(
                [
                    0x04,
                    0x6D,
                    0x35,
                    0xE7,
                    0xA0,
                    0x75,
                    0x42,
                    0xC1,
                    0x2C,
                    0x6D,
                    0x2A,
                    0x0D,
                    0x2D,
                    0x45,
                    0xA4,
                    0xE9,
                    0x46,
                    0x68,
                    0x95,
                    0x27,
                    0x65,
                    0xDA,
                    0x9F,
                    0x68,
                    0xB4,
                    0x7C,
                    0x75,
                    0x5F,
                    0x38,
                    0x00,
                    0xFB,
                    0x95,
                    0x85,
                    0xDD,
                    0x7D,
                    0xED,
                    0xA7,
                    0xDB,
                    0xFD,
                    0x2D,
                    0xF0,
                    0xD1,
                    0x2C,
                    0xF3,
                    0xCC,
                    0x3D,
                    0xB6,
                    0xA0,
                    0x75,
                    0xD6,
                    0xB9,
                    0x35,
                    0xA8,
                    0x2A,
                    0xAC,
                    0x3C,
                    0x38,
                    0xA5,
                    0xB7,
                    0xE8,
                    0x62,
                    0x80,
                    0x93,
                    0x84,
                    0x55,
                ]
            )
        )
        pkr = COSEKey.new(EC2Key.to_cose_key(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pkr_buf)))

        # t_cose/examples/keys/init_keys_psa.c:fixed_test_p256r1_private_key
        skr_buf = bytes(
            bytearray(
                [
                    0x37,
                    0x0B,
                    0xAF,
                    0x20,
                    0x45,
                    0x17,
                    0x01,
                    0xF6,
                    0x64,
                    0xE1,
                    0x28,
                    0x57,
                    0x4E,
                    0xB1,
                    0x7A,
                    0xD3,
                    0x5B,
                    0xDD,
                    0x96,
                    0x65,
                    0x0A,
                    0xA8,
                    0xA3,
                    0xCD,
                    0xBD,
                    0xD6,
                    0x6F,
                    0x57,
                    0xA8,
                    0xCC,
                    0xE8,
                    0x09,
                ]
            )
        )
        params = EC2Key.to_cose_key(ec.derive_private_key(int.from_bytes(skr_buf, byteorder="big"), ec.SECP256R1()))
        params[2] = b"fixed_test_key_p256r1"
        skr = COSEKey.new(params)

        # from the output of t_cose/examples/encryption_examples
        msg = bytes.fromhex(
            "d8608443a10101a10550d146ace746b2a860b273f03f0534d0bb58231405f78e061fb13f400df1bfd156c9b9f7460325dfe9adc762e9d208196a3bdfd8dc19818343a10120a22384100101584104371c3c31426b7f84340757509836ab7ed60bca356cf9570a2858473827297959633fd597bc4202b409552ada2c81825897eafb0a402d6ea2f74fbe0dcea2b47e045566697865645f746573745f6b65795f7032353672315820c452a5bc660a268fa04c05744d16f17dc28d7593897d2c3dbc54223d9ca5eec6"
        )

        # from the output of t_cose/examples/encryption_examples
        pt = bytes.fromhex("5468697320697320746865207061796c6f6164")

        recipient = COSE.new()
        assert pt == recipient.decode(msg, skr)
