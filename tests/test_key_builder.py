# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for KeyBuilder.
"""
import pytest

from cwt import COSEKey, KeyBuilder, cose_key

from .utils import key_path

# from secrets import token_bytes


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return KeyBuilder()


class TestKeyBuilder:
    """
    Tests for KeyBuilder.
    """

    def test_key_builder_constructor(self):
        """"""
        c = KeyBuilder()
        assert isinstance(c, KeyBuilder)

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
        ],
    )
    def test_key_builder_from_symmetric_key_hmac(self, ctx, alg):
        k = ctx.from_symmetric_key("mysecret", alg=alg)
        assert isinstance(k, COSEKey)

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
            "AES-CCM-16-64-128",
            "AES-CCM-16-64-256",
            "AES-CCM-64-64-128",
            "AES-CCM-64-64-256",
            "AES-CCM-16-128-128",
            "AES-CCM-16-128-256",
            "AES-CCM-64-128-128",
            "AES-CCM-64-128-256",
        ],
    )
    def test_key_builder_from_symmetric_key_without_key(self, ctx, alg):
        try:
            k = ctx.from_symmetric_key(alg=alg)
            assert k.kty == 4
        except Exception:
            pytest.fail("from_symmetric_key should not fail.")

    @pytest.mark.parametrize(
        "alg",
        ["xxx", 0, 8, 9, 34],
    )
    def test_key_builder_from_symmetric_key_with_invalid_alg(self, ctx, alg):
        with pytest.raises(ValueError) as err:
            ctx.from_symmetric_key("mysecretpassword", alg=alg)
            pytest.fail("from_symmetric_key should fail.")
        assert f"Unsupported or unknown alg({alg})." in str(err.value)

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.pem", "public_key_ed25519.pem"),
            ("private_key_ed448.pem", "public_key_ed448.pem"),
            ("private_key_es256.pem", "public_key_es256.pem"),
            ("private_key_es256k.pem", "public_key_es256k.pem"),
            ("private_key_es384.pem", "public_key_es384.pem"),
            ("private_key_es512.pem", "public_key_es512.pem"),
            ("private_key_x25519.pem", "public_key_x25519.pem"),
            ("private_key_x448.pem", "public_key_x448.pem"),
        ],
    )
    def test_key_builder_from_pem(self, private_key_path, public_key_path):
        try:
            with open(key_path(private_key_path)) as key_file:
                cose_key.from_pem(key_file.read())
            with open(key_path(public_key_path)) as key_file:
                cose_key.from_pem(key_file.read())
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "kid, expected",
        [
            (b"our-key", b"our-key"),
            ("our-key", b"our-key"),
        ],
    )
    def test_key_builder_from_pem_with_kid(self, kid, expected):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read(), kid=kid)
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read(), kid=kid)
        assert private_key.kid == expected
        assert public_key.kid == expected

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ("invalidstring", "Failed to decode PEM."),
            (b"invalidbytes", "Failed to decode PEM."),
        ],
    )
    def test_key_builder_from_pem_with_invalid_args(self, ctx, invalid, msg):
        with pytest.raises(ValueError) as err:
            ctx.from_pem(invalid)
            pytest.fail("from_pem should not fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ({}, "kty(1) not found."),
            ({1: b"kty"}, "kty(1) should be int or str(tstr)."),
            ({1: {}}, "kty(1) should be int or str(tstr)."),
            ({1: []}, "kty(1) should be int or str(tstr)."),
            ({1: 7}, "Unsupported or unknown kty(1): 7."),
            ({1: 4, 3: b"alg"}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: {}}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: []}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: 1}, "Unsupported or unknown alg(3): 1."),
        ],
    )
    def test_key_builder_from_dict_with_invalid_args(self, ctx, invalid, msg):
        with pytest.raises(ValueError) as err:
            ctx.from_dict(invalid)
            pytest.fail("from_dict should fail.")
        assert msg in str(err.value)

    def test_key_builder_from_jwk(self, ctx):
        with pytest.raises(NotImplementedError):
            ctx.from_jwk('{"kty":"OKP"}')
            pytest.fail("from_jwk should fail.")
