"""
Tests for Signer.
"""
import cbor2
import pytest

from cwt import COSEKey, Signer

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
            protected={1: -7},
            unprotected={4: b"01"},
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
            protected=cbor2.dumps({1: -7}),
            unprotected={4: b"01"},
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
        assert signer.unprotected[4] == b"01"
        assert cbor2.loads(signer.protected)[1] == -7
        assert signer.cose_key.alg == -7
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
            protected=cbor2.dumps({1: -7}),
            unprotected={"kid": "01"},
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
        assert signer.unprotected[4] == b"01"
        assert cbor2.loads(signer.protected)[1] == -7
        assert signer.cose_key.alg == -7
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
        assert cbor2.loads(signer.protected)[1] == -7
        assert signer.cose_key.alg == -7
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
        assert signer.unprotected[4] == b"01"
        assert cbor2.loads(signer.protected)[1] == -8
        assert signer.cose_key.alg == -8
        assert signer.cose_key.kid == b"01"
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")

    def test_signer_from_pem_without_kid(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read())
        assert cbor2.loads(signer.protected)[1] == -8
        assert signer.cose_key.alg == -8
        assert signer.cose_key.kid is None
        try:
            signer.sign(b"Hello world!")
            signer.verify(b"Hello world!")
        except Exception:
            pytest.fail("signer.sign and verify should not fail.")
