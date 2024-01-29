"""
Tests for OKPKey.
"""

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cwt.algs.okp import OKPKey
from cwt.cose_key import COSEKey
from cwt.enums import COSEAlgs, COSEKeyCrvs, COSEKeyOps, COSEKeyParams, COSEKeyTypes
from cwt.exceptions import VerifyError

from .utils import key_path


class TestOKPKey:
    """
    Tests for OKPKey.
    """

    def test_okp_key_constructor_with_ed25519_key(self):
        private_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            }
        )
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        assert private_key.kty == 1
        assert private_key.kid is None
        assert isinstance(private_key.key, Ed25519PrivateKey)
        assert private_key.alg == -8
        assert private_key.crv == 6
        assert len(private_key.key_ops) == 2
        assert 1 in private_key.key_ops
        assert 2 in private_key.key_ops
        assert private_key.base_iv is None
        assert public_key.kty == 1
        assert public_key.kid is None
        assert public_key.alg == -8
        assert public_key.crv == 6
        assert len(public_key.key_ops) == 1
        assert 2 in public_key.key_ops
        assert public_key.base_iv is None
        private_key_obj = private_key.to_dict()
        assert (
            private_key_obj[-4] == b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9"
        )
        public_key_obj = public_key.to_dict()
        assert (
            public_key_obj[-2]
            == b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9"
        )
        try:
            sig = private_key.sign(b"Hello world!")
            public_key.verify(b"Hello world!", sig)
        except Exception:
            pytest.fail("sign/verify should not fail.")

    def test_okp_key_constructor_with_ed448_key(self):
        private_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED448,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\xdb\x98\xacQb(\xb1I\x0c\xdb)\xce<S\xf9\xb7\xb0[\xc0\xcd\x7f\x88T&(\x1aG\xbc\r!\x81zQ_\xac\xb2\xbb\xe9\xea\xe8\x10f\xa5-\xc9\xd06\x13\x95\x92(\x03\x8a\xb0\x81*\x80",
                COSEKeyParams.D: b"\xbc\xe1\xe0\xdf\x1f@\\@Q\x0e|\xcc\xe5\xbe\xbcl\xb1l\xc2'\xb2\xc2\x92sL\xe91i\xf59~ \xf1\xc8\xaa0\xb9\xebg\x06\x08\xd0\xb2\x04\xd1Z\x874\xeb\xb5\xfd\xc6\xf6V\x13D\x9d",
            }
        )
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED448,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\xdb\x98\xacQb(\xb1I\x0c\xdb)\xce<S\xf9\xb7\xb0[\xc0\xcd\x7f\x88T&(\x1aG\xbc\r!\x81zQ_\xac\xb2\xbb\xe9\xea\xe8\x10f\xa5-\xc9\xd06\x13\x95\x92(\x03\x8a\xb0\x81*\x80",
            }
        )
        assert private_key.kty == 1
        assert private_key.kid is None
        assert private_key.alg == -8
        assert private_key.crv == 7
        assert len(private_key.key_ops) == 2
        assert 1 in private_key.key_ops
        assert 2 in private_key.key_ops
        assert private_key.base_iv is None
        assert public_key.kty == 1
        assert public_key.kid is None
        assert public_key.alg == -8
        assert public_key.crv == 7
        assert len(public_key.key_ops) == 1
        assert 2 in public_key.key_ops
        assert public_key.base_iv is None
        private_key_obj = private_key.to_dict()
        assert (
            private_key_obj[-4]
            == b"\xbc\xe1\xe0\xdf\x1f@\\@Q\x0e|\xcc\xe5\xbe\xbcl\xb1l\xc2'\xb2\xc2\x92sL\xe91i\xf59~ \xf1\xc8\xaa0\xb9\xebg\x06\x08\xd0\xb2\x04\xd1Z\x874\xeb\xb5\xfd\xc6\xf6V\x13D\x9d"
        )
        public_key_obj = public_key.to_dict()
        assert (
            public_key_obj[-2]
            == b"\xdb\x98\xacQb(\xb1I\x0c\xdb)\xce<S\xf9\xb7\xb0[\xc0\xcd\x7f\x88T&(\x1aG\xbc\r!\x81zQ_\xac\xb2\xbb\xe9\xea\xe8\x10f\xa5-\xc9\xd06\x13\x95\x92(\x03\x8a\xb0\x81*\x80"
        )
        try:
            sig = private_key.sign(b"Hello world!")
            public_key.verify(b"Hello world!", sig)
        except Exception:
            pytest.fail("sign/verify should not fail.")

    def test_okp_key_constructor_with_x25519_key(self):
        private_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                COSEKeyParams.D: b"\xbe\xc2u\xa1~M6-\x08\x19\xdc\x06\x95\xd8\x9as\xbek\xf9Kf\xabrj\xe0\xb1\xaf\xe3\xc4?A\xce",
                COSEKeyParams.X: b'\xcb|\t\xab{\x97<w\xa8\x08\xee\x05\xb9\xbb\xd3s\xb5\\\x06\xea\xa9\xbdJ\xd2\xbdN\x991\xb1\xc3L"',
            }
        )
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                COSEKeyParams.X: b'\xcb|\t\xab{\x97<w\xa8\x08\xee\x05\xb9\xbb\xd3s\xb5\\\x06\xea\xa9\xbdJ\xd2\xbdN\x991\xb1\xc3L"',
                COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
            }
        )
        assert private_key.kty == 1
        assert private_key.kid is None
        assert private_key.alg == COSEAlgs.ECDH_ES_HKDF_256
        assert private_key.crv == 4
        assert len(private_key.key_ops) == 2
        assert 7 in private_key.key_ops
        assert 8 in private_key.key_ops
        assert private_key.base_iv is None

        assert public_key.kty == 1
        assert public_key.kid is None
        assert public_key.alg == COSEAlgs.ECDH_ES_HKDF_256
        assert public_key.crv == 4
        assert len(public_key.key_ops) == 0
        assert public_key.base_iv is None
        private_key_obj = private_key.to_dict()
        assert (
            private_key_obj[-4] == b"\xbe\xc2u\xa1~M6-\x08\x19\xdc\x06\x95\xd8\x9as\xbek\xf9Kf\xabrj\xe0\xb1\xaf\xe3\xc4?A\xce"
        )
        public_key_obj = public_key.to_dict()
        assert (
            public_key_obj[-2]
            == b'\xcb|\t\xab{\x97<w\xa8\x08\xee\x05\xb9\xbb\xd3s\xb5\\\x06\xea\xa9\xbdJ\xd2\xbdN\x991\xb1\xc3L"'
        )

    def test_okp_key_constructor_with_x25519_key_without_key(self):
        try:
            OKPKey(
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b'\xcb|\t\xab{\x97<w\xa8\x08\xee\x05\xb9\xbb\xd3s\xb5\\\x06\xea\xa9\xbdJ\xd2\xbdN\x991\xb1\xc3L"',
                }
            )
        except Exception:
            pytest.fail("OKPKey() should not fail.")

    def test_okp_key_constructor_with_x448_key(self):
        private_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.X448,
                COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                COSEKeyParams.D: b"\xac\x92Q\x1by\xec\x87 \xadw\xd0\xa0^W|h\xd6\x81\xf5\x85\xcaGE\x0e\x8b\xbc\xe3\xee\x10)\x83\xd6\x07\xe1wA;A\xbc5\xc0\x057?\xee<}\x86\x9c&Uq \xe0W\x97",
                COSEKeyParams.X: b'"B\xe6sI%\xbcC\x17bw\x870\xa0\x01\xe9\xe3\xe8\x86\xbc\x80\xc0\x03\xd5{jQI\xf7\xc8\r\x8e\x8d\xae7\x985eW\xe4\x9f\x9f\x1b\x83U\xd8\xea\x14\xef\xb0\xbc\xf0\r&\xbf\x12',
            }
        )
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.X448,
                COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                COSEKeyParams.X: b'"B\xe6sI%\xbcC\x17bw\x870\xa0\x01\xe9\xe3\xe8\x86\xbc\x80\xc0\x03\xd5{jQI\xf7\xc8\r\x8e\x8d\xae7\x985eW\xe4\x9f\x9f\x1b\x83U\xd8\xea\x14\xef\xb0\xbc\xf0\r&\xbf\x12',
            }
        )
        assert private_key.kty == 1
        assert private_key.kid is None
        assert private_key.alg == COSEAlgs.ECDH_ES_HKDF_256
        assert private_key.crv == 5
        assert len(private_key.key_ops) == 2
        assert 7 in private_key.key_ops
        assert 8 in private_key.key_ops
        assert private_key.base_iv is None

        assert public_key.kty == 1
        assert public_key.kid is None
        assert public_key.alg == COSEAlgs.ECDH_ES_HKDF_256
        assert public_key.crv == 5
        assert len(public_key.key_ops) == 0
        assert public_key.base_iv is None
        private_key_obj = private_key.to_dict()

        assert (
            private_key_obj[-4]
            == b"\xac\x92Q\x1by\xec\x87 \xadw\xd0\xa0^W|h\xd6\x81\xf5\x85\xcaGE\x0e\x8b\xbc\xe3\xee\x10)\x83\xd6\x07\xe1wA;A\xbc5\xc0\x057?\xee<}\x86\x9c&Uq \xe0W\x97"
        )
        public_key_obj = public_key.to_dict()
        assert (
            public_key_obj[-2]
            == b'"B\xe6sI%\xbcC\x17bw\x870\xa0\x01\xe9\xe3\xe8\x86\xbc\x80\xc0\x03\xd5{jQI\xf7\xc8\r\x8e\x8d\xae7\x985eW\xe4\x9f\x9f\x1b\x83U\xd8\xea\x14\xef\xb0\xbc\xf0\r&\xbf\x12'
        )

    def test_okp_key_validate_certificate_with_empty_ca_certs(self):
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        with pytest.raises(ValueError) as err:
            public_key.validate_certificate(ca_certs=[])
            pytest.fail("validate_certificate() should fail.")
        assert "ca_certs should be set." in str(err.value)

    def test_okp_key_validate_certificate_without_x5c(self):
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        assert public_key.validate_certificate(ca_certs=[b"xxxxx"]) is False

    @pytest.mark.parametrize(
        "alg",
        [
            "A128GCM",
            "AES-CCM-16-64-128",
            "ChaCha20/Poly1305",
        ],
    )
    def test_okp_key_derive_bytes(self, alg):
        with open(key_path("private_key_x25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                # "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        try:
            private_key.derive_bytes(16, b"xxxxxxxx", b"xxxxxxxx", public_key=pub_key)
        except Exception:
            pytest.fail("derive_bytes() should not fail.")

    def test_okp_key_derive_bytes_with_raw_context(self):
        with open(key_path("private_key_x25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                # "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        context = [
            1,
            [None, None, None],
            [None, None, None],
            [128, cbor2.dumps({1: COSEAlgs.ECDH_ES_HKDF_256})],
        ]
        try:
            private_key.derive_bytes(16, b"xxxxxxxx", info=cbor2.dumps(context), public_key=pub_key)
        except Exception:
            pytest.fail("derive_bytes() should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {COSEKeyParams.KTY: 2},
                "kty(1) should be OKP(1).",
            ),
            (
                {COSEKeyParams.KTY: b"invalid"},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: {}},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: []},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP},
                "crv(-1) not found.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "crv(-1) not found.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.CRV: {}},
                "crv(-1) should be int.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.CRV: []},
                "crv(-1) should be int.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.CRV: "Ed25519"},
                "crv(-1) should be int.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.OKP, COSEKeyParams.CRV: 0},
                "Unsupported or unknown crv(-1) for OKP: 0.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: 3,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "Unsupported or unknown crv(-1) for OKP: 3.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: 8,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "Unsupported or unknown crv(-1) for OKP: 8.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.ALG: -999,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "Unsupported or unknown alg used with Ed25519/Ed448: -999.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.ALG: 35,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "Unsupported or unknown alg used with Ed25519/Ed448: 35.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.X: "xxxxxxxxxxxxxxxx",
                },
                "x(-2) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.X: {},
                },
                "x(-2) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.X: [],
                },
                "x(-2) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.X: b"invalid-x",
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                },
                "Invalid key parameter.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: "invalid-type-d",
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: {},
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: [],
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: 123,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"invalid-d",
                },
                "Invalid key parameter.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Invalid key_ops for signing key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Signing key should not be used for key derivation.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                    ],
                },
                "Invalid key_ops for public key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                    ],
                },
                "Invalid key_ops for key derivation.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                    ],
                },
                "Invalid key_ops for key derivation.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Private key for ECDHE should not be used for signing.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Public key for ECDHE should not have key_ops.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: "invalid-type-x",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [],
                },
                "x(-2) should be bytes(bstr).",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Invalid key_ops for Ed25519/448 private key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.SIGN,
                        COSEKeyOps.VERIFY,
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Invalid key_ops for Ed25519/448 public key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "Invalid key_ops for Ed25519/448 public key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    33: 123,
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "x5c(33) should be bytes(bstr) or list.",
            ),
            # (
            #     {
            #         COSEKeyParams.KTY: COSEKeyTypes.OKP,
            #         COSEKeyParams.CRV: COSEKeyCrvs.X25519,
            #         COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            #         COSEKeyParams.KEY_OPS: [
            #             COSEKeyOps.DERIVE_KEY,
            #             COSEKeyOps.DERIVE_BITS,
            #         ],
            #     },
            #     "X25519/X448 needs alg explicitly.",
            # ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    # COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.VERIFY,
                    ],
                },
                "x(-2) not found.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.VERIFY,
                    ],
                },
                "Unsupported or unknown alg used with X25519/X448: -8.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "The body of the key not found.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    # COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [
                        COSEKeyOps.DERIVE_KEY,
                        COSEKeyOps.DERIVE_BITS,
                    ],
                },
                "x(-2) not found.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN],
                },
                "Invalid key_ops for X25519/448 private key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.DERIVE_KEY, COSEKeyOps.SIGN],
                },
                "Invalid key_ops for X25519/448 private key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                    # COSEKeyParams.ALG: COSEAlgs.EDDSA,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.DERIVE_KEY],
                },
                "Invalid key_ops for Ed25519/448 private key.",
            ),
            (
                {
                    COSEKeyParams.KTY: COSEKeyTypes.OKP,
                    COSEKeyParams.CRV: COSEKeyCrvs.X25519,
                    # COSEKeyParams.ALG: COSEAlgs.ECDH_ES_HKDF_256,
                    COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    # COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.DERIVE_KEY],
                },
                "Invalid key_ops for X25519/448 public key.",
            ),
        ],
    )
    def test_okp_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            OKPKey(invalid)
            pytest.fail("OKPKey should fail.")
        assert msg in str(err.value)

    def test_okp_key_sign_with_es256_public_key(self):
        public_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        with pytest.raises(ValueError) as err:
            public_key.sign(b"Hello world!")
            pytest.fail("sign should not fail.")
        assert "Public key cannot be used for signing." in str(err.value)

    def test_okp_key_verify_with_invalid_signature(self):
        private_key = OKPKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.OKP,
                COSEKeyParams.CRV: COSEKeyCrvs.ED25519,
                COSEKeyParams.ALG: COSEAlgs.EDDSA,
                COSEKeyParams.X: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                COSEKeyParams.D: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            }
        )
        sig = private_key.sign(b"Hello world!")
        with pytest.raises(VerifyError) as err:
            private_key.verify(b"Hello world!", sig + b"xxx")
            pytest.fail("verify should not fail.")
        assert "Failed to verify." in str(err.value)

    def test_okp_key_derive_bytes_with_public_key(self):
        with open(key_path("public_key_x25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                # "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        with pytest.raises(ValueError) as err:
            public_key.derive_bytes(b"xxxxxxxx", public_key=pub_key)
        assert "Public key cannot be used for key derivation." in str(err.value)

    def test_okp_key_derive_bytes_without_public_key(self):
        with open(key_path("private_key_x25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        with pytest.raises(ValueError) as err:
            private_key.derive_bytes(16, b"xxxxxxxx", b"xxxxxxxx")
        assert "public_key should be set." in str(err.value)

    def test_okp_key_derive_bytes_with_ed25519_key(self):
        with open(key_path("private_key_x25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                # "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        with pytest.raises(ValueError) as err:
            private_key.derive_bytes(16, b"xxxxxxxx", b"xxxxxxxx", public_key=pub_key)
        assert "public_key should be x25519/x448 public key." in str(err.value)

    def test_okp_key_to_cose_key_with_invalid_key(self):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        with pytest.raises(ValueError) as err:
            OKPKey.to_cose_key(private_key.key)
        assert "Unsupported or unknown key for OKP." in str(err.value)

    @pytest.mark.parametrize(
        "alg, key_ops",
        [
            (
                "HPKE-Base-X25519-SHA256-AES128GCM",
                ["deriveBits"],
            ),
            (
                "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
                ["deriveBits"],
            ),
        ],
    )
    def test_okp_key_private_with_alg_hpke(self, alg, key_ops):
        try:
            _ = COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "alg": alg,
                    "kid": "01",
                    "crv": "X25519",
                    "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                    "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
                    "key_ops": key_ops,
                }
            )
        except Exception:
            pytest.fail("from_jwk should not fail.")

    @pytest.mark.parametrize(
        "alg, key_ops",
        [
            (
                "HPKE-Base-X25519-SHA256-AES128GCM",
                [],
            ),
            (
                "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
                [],
            ),
        ],
    )
    def test_okp_key_public_with_alg_hpke(self, alg, key_ops):
        try:
            _ = COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "alg": alg,
                    "kid": "01",
                    "crv": "X25519",
                    "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                    # "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
                    "key_ops": key_ops,
                }
            )
        except Exception:
            pytest.fail("from_jwk should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                0,
                "key_ops should be list.",
            ),
            (
                [],
                "Invalid key_ops for HPKE private key.",
            ),
            (
                ["sign"],
                "Invalid key_ops for HPKE private key.",
            ),
            (
                ["deriveKey"],
                "Invalid key_ops for HPKE private key.",
            ),
            (
                ["deriveKey", "deriveBits"],
                "Invalid key_ops for HPKE private key.",
            ),
        ],
    )
    def test_okp_key_private_with_alg_hpke_and_invalid_key_ops(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "alg": "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
                    "kid": "01",
                    "crv": "X25519",
                    "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                    "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
                    "key_ops": invalid,
                }
            )
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                0,
                "key_ops should be list.",
            ),
            (
                ["sign"],
                "Invalid key_ops for HPKE public key.",
            ),
            (
                ["deriveKey"],
                "Invalid key_ops for HPKE public key.",
            ),
            (
                ["deriveBits"],
                "Invalid key_ops for HPKE public key.",
            ),
            (
                ["deriveKey", "deriveBits"],
                "Invalid key_ops for HPKE public key.",
            ),
        ],
    )
    def test_okp_key_public_with_alg_hpke_and_invalid_key_ops(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKey.from_jwk(
                {
                    "kty": "OKP",
                    "alg": "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
                    "kid": "01",
                    "crv": "X25519",
                    "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                    "key_ops": invalid,
                }
            )
            pytest.fail("COSEKey.from_jwk should fail.")
        assert msg in str(err.value)
