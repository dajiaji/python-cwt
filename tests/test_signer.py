"""
Tests for Signer.
"""

import cbor2
import pytest

from cwt import COSEKey, Signer
from cwt.enums import COSEAlgs, COSEHeaders

from .utils import key_path


class TestSigner:
    """
    Tests for Signer.
    """

    def test_signer_constructor(self):
        signer = Signer(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected={COSEHeaders.ALG: COSEAlgs.ES256},
            unprotected={COSEHeaders.KID: b"01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_constructor_with_protected_bytes(self):
        signer = Signer(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected=cbor2.dumps({COSEHeaders.ALG: COSEAlgs.ES256}),
            unprotected={COSEHeaders.KID: b"01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_new(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected={"alg": "ES256"},
            unprotected={"kid": "01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_new_with_protected_bytes(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected=cbor2.dumps({COSEHeaders.ALG: COSEAlgs.ES256}),
            unprotected={"kid": "01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_jwt(self):
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            },
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_jwt_without_kid(self):
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            },
        )
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ES256
        assert signer.cose_key.alg == COSEAlgs.ES256
        assert signer.cose_key.kid is None
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_jwt_with_key_ops(self):
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                "key_ops": ["sign", "verify"],
            },
        )
        assert signer.unprotected[4] == b"01"
        assert cbor2.loads(signer.protected)[1] == -7
        assert signer.cose_key.alg == -7
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_jwk_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            Signer.from_jwk({"kty": "oct", "alg": "HS256", "kid": "01", "k": "xxxxxxxxxx"})
        assert "Unsupported or unknown alg for signature: 5." in str(err.value)

    def test_signer_from_jwt_with_invalid_key_ops(self):
        with pytest.raises(ValueError) as err:
            Signer.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                    "key_ops": ["encrypt", "decrypt"],
                },
            )
        assert "Unknown or not permissible key_ops(4) for EC2." in str(err.value)

    def test_signer_from_pem(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read(), kid="01")
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.EDDSA
        assert signer.cose_key.alg == COSEAlgs.EDDSA
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_pem_without_kid(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read())
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.EDDSA
        assert signer.cose_key.alg == COSEAlgs.EDDSA
        assert signer.cose_key.kid is None
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_esp256(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                    "alg": "ESP256",
                }
            ),
            protected={"alg": "ESP256"},
            unprotected={"kid": "01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ESP256
        assert signer.cose_key.alg == COSEAlgs.ESP256
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_esp384(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "P-384-01",
                    "crv": "P-384",
                    "x": "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
                    "y": "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
                    "d": "1pImEKbrr771-RKi8Tb7tou_WjiR7kwui_nMu16449rk3lzAqf9buUhTkJ-pogkb",
                    "alg": "ESP384",
                }
            ),
            protected={"alg": "ESP384"},
            unprotected={"kid": "P-384-01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"P-384-01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ESP384
        assert signer.cose_key.alg == COSEAlgs.ESP384
        assert signer.cose_key.kid == b"P-384-01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_esp512(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "P-521-01",
                    "crv": "P-521",
                    "x": "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
                    "y": "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
                    "d": "ADYyo73ZKicOjwGDYQ_ybZKnVzdAcxGm9OVAxQjzgVM4jaS-Iwtkz90oLdDz3shgKlDgtRK2Aa9lMhqR94hBo4IE",
                    "alg": "ESP512",
                }
            ),
            protected={"alg": "ESP512"},
            unprotected={"kid": "P-521-01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"P-521-01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ESP512
        assert signer.cose_key.alg == COSEAlgs.ESP512
        assert signer.cose_key.kid == b"P-521-01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_ed25519(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
                    "use": "sig",
                    "crv": "Ed25519",
                    "kid": "Ed25519-01",
                    "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                    "alg": "Ed25519",
                }
            ),
            protected={"alg": "Ed25519"},
            unprotected={"kid": "Ed25519-01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"Ed25519-01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ED25519
        assert signer.cose_key.alg == COSEAlgs.ED25519
        assert signer.cose_key.kid == b"Ed25519-01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_ed448(self):
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "d": "vOHg3x9AXEBRDnzM5b68bLFswieywpJzTOkxafU5fiDxyKowuetnBgjQsgTRWoc067X9xvZWE0Sd",
                    "use": "sig",
                    "crv": "Ed448",
                    "kid": "Ed448-01",
                    "x": "25isUWIosUkM2ynOPFP5t7BbwM1_iFQmKBpHvA0hgXpRX6yyu-nq6BBmpS3J0DYTlZIoA4qwgSqA",
                    "alg": "Ed448",
                }
            ),
            protected={"alg": "Ed448"},
            unprotected={"kid": "Ed448-01"},
        )
        assert signer.unprotected[COSEHeaders.KID] == b"Ed448-01"
        assert cbor2.loads(signer.protected)[COSEHeaders.ALG] == COSEAlgs.ED448
        assert signer.cose_key.alg == COSEAlgs.ED448
        assert signer.cose_key.kid == b"Ed448-01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")
