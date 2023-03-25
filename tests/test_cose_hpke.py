# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

from cryptography.hazmat.primitives.asymmetric import ec
import pytest

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

        pkr_buf = bytes(bytearray([
            0x04, 0x6d, 0x35, 0xe7, 0xa0, 0x75, 0x42, 0xc1, 0x2c, 0x6d, 0x2a, 0x0d,
            0x2d, 0x45, 0xa4, 0xe9, 0x46, 0x68, 0x95, 0x27, 0x65, 0xda, 0x9f, 0x68,
            0xb4, 0x7c, 0x75, 0x5f, 0x38, 0x00, 0xfb, 0x95, 0x85, 0xdd, 0x7d, 0xed,
            0xa7, 0xdb, 0xfd, 0x2d, 0xf0, 0xd1, 0x2c, 0xf3, 0xcc, 0x3d, 0xb6, 0xa0,
            0x75, 0xd6, 0xb9, 0x35, 0xa8, 0x2a, 0xac, 0x3c, 0x38, 0xa5, 0xb7, 0xe8,
            0x62, 0x80, 0x93, 0x84, 0x55
        ]))
        pkr = COSEKey.new(EC2Key.to_cose_key(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pkr_buf)))

        skr_buf = bytes(bytearray([
            0x37, 0x0b, 0xaf, 0x20, 0x45, 0x17, 0x01, 0xf6, 0x64, 0xe1, 0x28, 0x57,
            0x4e, 0xb1, 0x7a, 0xd3, 0x5b, 0xdd, 0x96, 0x65, 0x0a, 0xa8, 0xa3, 0xcd,
            0xbd, 0xd6, 0x6f, 0x57, 0xa8, 0xcc, 0xe8, 0x09
        ]))
        params = EC2Key.to_cose_key(ec.derive_private_key(int.from_bytes(skr_buf, byteorder="big"), ec.SECP256R1()))
        params[2] = b"fixed_test_key_p256r1"
        skr = COSEKey.new(params)

        msg = bytes.fromhex("d8608443a10101a10550ff96274fe513d6d5556bd5149e954c53582305126370fc3fbfc1d1bc1710d58e6de52be729d30db2497a10f83e52edd29438fb9809818343a10120a2238410010158410403be32ff3820be4f311e0112d2bd58b907d5a33141a5d112f6729669f9f310a11774246487d404b96e32300eb4b18de88d32bb85458cc126fc8a6f2f59ce888e045566697865645f746573745f6b65795f7032353672315820bc7b8684ba8b5170f04fa6feccc338266cfe7b278bd95b1c03bad0023f58f880")

        pt = bytes.fromhex("5468697320697320746865207061796c6f6164")

        recipient = COSE.new()
        assert pt == recipient.decode(msg, skr)
