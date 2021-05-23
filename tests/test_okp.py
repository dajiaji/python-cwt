"""
Tests for OKPKey.
"""
import pytest

from cwt.algs.okp import OKPKey
from cwt.exceptions import VerifyError


class TestOKPKey:
    """
    Tests for OKPKey.
    """

    def test_okp_key_constructor_with_ed25519_key(self):
        private_key = OKPKey(
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                -4: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            }
        )
        public_key = OKPKey(
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        assert private_key.kty == 1
        assert private_key.kid is None
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
            private_key_obj[-4]
            == b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9"
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

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be OKP(1).",
            ),
            (
                {1: b"invalid"},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: {}},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: []},
                "kty(1) should be int or str(tstr).",
            ),
            (
                {1: 1},
                "x(-2) not found.",
            ),
            (
                {1: 1, -2: "xxxxxxxxxxxxxxxx"},
                "x(-2) should be bytes(bstr).",
            ),
            (
                {1: 1, -2: {}},
                "x(-2) should be bytes(bstr).",
            ),
            (
                {1: 1, -2: []},
                "x(-2) should be bytes(bstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    3: -1,
                },
                "OKP algorithm mismatch: -1.",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                },
                "crv(-1) not found.",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -1: {},
                },
                "crv(-1) should be int or str(tstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -1: [],
                },
                "crv(-1) should be int or str(tstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -1: b"EdDSA",
                },
                "crv(-1) should be int or str(tstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -1: 3,
                },
                "Unsupported or unknown curve(3) for OKP.",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -1: 8,
                },
                "Unsupported or unknown curve(8) for OKP.",
            ),
            (
                {1: 1, -2: b"invalid-x", -1: 6},
                "Invalid key parameter.",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -4: "invalid-type-d",
                    -1: 6,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -4: {},
                    -1: 6,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -4: [],
                    -1: 6,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -4: 123,
                    -1: 6,
                },
                "d(-4) should be bytes(bstr).",
            ),
            (
                {
                    1: 1,
                    -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                    -4: b"invalid-d",
                    -1: 6,
                },
                "Invalid key parameter.",
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
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            }
        )
        with pytest.raises(ValueError) as err:
            public_key.sign(b"Hello world!")
            pytest.fail("sign should not fail.")
        assert "Public key cannot be used for signing." in str(err.value)

    def test_okp_key_verify_with_invalid_signature(self):
        private_key = OKPKey(
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                -4: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            }
        )
        sig = private_key.sign(b"Hello world!")
        with pytest.raises(VerifyError) as err:
            private_key.verify(b"Hello world!", sig + b"xxx")
            pytest.fail("verify should not fail.")
        assert "Failed to verify." in str(err.value)
