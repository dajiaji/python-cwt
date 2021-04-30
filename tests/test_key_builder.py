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
        c = KeyBuilder()
        assert isinstance(c, KeyBuilder)

    @pytest.mark.parametrize(
        "alg, alg_label",
        [
            ("HMAC 256/64", 4),
            ("HMAC 256/256", 5),
            ("HMAC 384/384", 6),
            ("HMAC 512/512", 7),
        ],
    )
    def test_key_builder_from_symmetric_key_hmac(self, ctx, alg, alg_label):
        k = ctx.from_symmetric_key("mysecret", alg=alg)
        assert isinstance(k, COSEKey)
        assert k.alg == alg_label
        assert 9 in k.key_ops
        assert 10 in k.key_ops

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
        "alg, key_ops, expected",
        [
            ("HMAC 256/64", [9, 10], [9, 10]),
            ("HMAC 256/256", [9, 10], [9, 10]),
            ("HMAC 384/384", [9, 10], [9, 10]),
            ("HMAC 512/512", [9, 10], [9, 10]),
            ("HMAC 256/64", [9], [9]),
            ("HMAC 256/64", [10], [10]),
            ("HMAC 256/64", ["MAC create", "MAC verify"], [9, 10]),
            ("HMAC 256/64", ["MAC create"], [9]),
            ("HMAC 256/64", ["MAC verify"], [10]),
            ("A128GCM", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("A192GCM", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("A256GCM", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("A128GCM", [3, 4], [3, 4]),
            ("A128GCM", [5, 6], [5, 6]),
            ("A128GCM", ["encrypt", "decrypt"], [3, 4]),
            ("A128GCM", ["wrap key", "unwrap key"], [5, 6]),
            ("AES-CCM-16-64-128", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-16-64-256", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-64-64-128", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-64-64-256", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-16-128-128", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-16-128-256", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-64-128-128", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-64-128-256", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("AES-CCM-16-64-128", [3, 4], [3, 4]),
            ("AES-CCM-16-64-128", [5, 6], [5, 6]),
            ("AES-CCM-16-64-128", ["encrypt", "decrypt"], [3, 4]),
            ("AES-CCM-16-64-128", ["wrap key", "unwrap key"], [5, 6]),
            ("ChaCha20/Poly1305", [3, 4, 5, 6], [3, 4, 5, 6]),
            ("ChaCha20/Poly1305", [3, 4], [3, 4]),
            ("ChaCha20/Poly1305", [5, 6], [5, 6]),
            ("ChaCha20/Poly1305", ["encrypt", "decrypt"], [3, 4]),
            ("ChaCha20/Poly1305", ["wrap key", "unwrap key"], [5, 6]),
        ],
    )
    def test_key_builder_from_symmetric_key_with_key_ops(
        self, ctx, alg, key_ops, expected
    ):
        k = ctx.from_symmetric_key(alg=alg, key_ops=key_ops)
        assert len(k.key_ops) == len(key_ops)
        for ops in k.key_ops:
            assert ops in expected

    @pytest.mark.parametrize(
        "alg",
        ["xxx", 0, 8, 9, 34],
    )
    def test_key_builder_from_symmetric_key_with_invalid_alg(self, ctx, alg):
        with pytest.raises(ValueError) as err:
            ctx.from_symmetric_key("mysecret", alg=alg)
            pytest.fail("from_symmetric_key should fail.")
        assert f"Unsupported or unknown alg(3): {alg}." in str(err.value)

    @pytest.mark.parametrize(
        "key_ops",
        [["xxx"], ["MAC create", "MAC verify", "xxx"]],
    )
    def test_key_builder_from_symmetric_key_with_invalid_key_ops(self, ctx, key_ops):
        with pytest.raises(ValueError) as err:
            ctx.from_symmetric_key("mysecret", key_ops=key_ops)
            pytest.fail("from_symmetric_key should fail.")
        assert "Unsupported or unknown key_ops." in str(err.value)

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
        "key_ops, expected",
        [
            ([2], [2]),
            (["verify"], [2]),
        ],
    )
    def test_key_builder_from_pem_public_with_key_ops(self, key_ops, expected):
        with open(key_path("public_key_ed25519.pem")) as key_file:
            k = cose_key.from_pem(key_file.read(), key_ops=key_ops)
        assert len(k.key_ops) == len(key_ops)
        for ops in k.key_ops:
            assert ops in expected

    @pytest.mark.parametrize(
        "key_ops, expected",
        [
            ([1, 2], [1, 2]),
            (["sign", "verify"], [1, 2]),
            (["verify"], [2]),
            (["sign"], [1]),
        ],
    )
    def test_key_builder_from_pem_private_with_key_ops(self, key_ops, expected):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            k = cose_key.from_pem(key_file.read(), key_ops=key_ops)
        assert len(k.key_ops) == len(key_ops)
        for ops in k.key_ops:
            assert ops in expected

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ("invalidstring", "Failed to decode PEM."),
            (b"invalidbytes", "Failed to decode PEM."),
        ],
    )
    def test_key_builder_from_pem_with_invalid_key(self, ctx, invalid, msg):
        with pytest.raises(ValueError) as err:
            ctx.from_pem(invalid)
            pytest.fail("from_pem should not fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ([1], "Unknown or not permissible key_ops(4) for SignatureKey: 1"),
            (["sign"], "Unknown or not permissible key_ops(4) for SignatureKey: 1"),
        ],
    )
    def test_key_builder_from_pem_public_with_invalid_key_ops(self, ctx, invalid, msg):
        with open(key_path("public_key_ed25519.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                cose_key.from_pem(key_file.read(), key_ops=invalid)
                pytest.fail("from_pem should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ([9], "Unknown or not permissible key_ops(4) for SignatureKey: 9"),
            (
                ["MAC create"],
                "Unknown or not permissible key_ops(4) for SignatureKey: 9",
            ),
            (["xxx"], "Unsupported or unknown key_ops."),
        ],
    )
    def test_key_builder_from_pem_private_with_invalid_key_ops(self, ctx, invalid, msg):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                cose_key.from_pem(key_file.read(), key_ops=invalid)
                pytest.fail("from_pem should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "cose_key",
        [
            # OKP
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                -4: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            },
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            },
            # EC2
            {
                1: 2,
                3: 1,
                -2: b"\xa7\xddc*\xff\xc2?\x8b\xf8\x9c:\xad\xccDF\x9cZ \x04P\xef\x99\x0c=\xe6 w1\x08&\xba\xd9",
                -3: b"\xe2\xdb\xef\xfe\xb8\x8a\x12\xf27\xcb\x15:\x8a\xb9\x1a90B\x1a\x19^\xbc\xdc\xde\r\xb9s\xc1P\xf3\xaa\xdd",
                -4: b'\xe9\x16\x0c\xa96\x8d\xfa\xbc\xd5\xda"ua\xec\xf7\x96\r\x15\xf7_\xf3rb{\xb1\xde;\x99\x88\xafNh',
                -1: 1,
            },
            {
                1: 2,
                3: 1,
                -2: b"\xa7\xddc*\xff\xc2?\x8b\xf8\x9c:\xad\xccDF\x9cZ \x04P\xef\x99\x0c=\xe6 w1\x08&\xba\xd9",
                -3: b"\xe2\xdb\xef\xfe\xb8\x8a\x12\xf27\xcb\x15:\x8a\xb9\x1a90B\x1a\x19^\xbc\xdc\xde\r\xb9s\xc1P\xf3\xaa\xdd",
                -1: 1,
            },
            # Symmetric
            {1: 4, 3: 1},
            {1: 4, 3: 2},
            {1: 4, 3: 3},
            {1: 4, 3: 4},
            {1: 4, 3: 5},
            {1: 4, 3: 6},
            {1: 4, 3: 7},
            {1: 4, 3: 10},
            {1: 4, 3: 11},
            {1: 4, 3: 12},
            {1: 4, 3: 13},
            {1: 4, 3: 24},
            {1: 4, 3: 30},
            {1: 4, 3: 31},
            {1: 4, 3: 32},
            {1: 4, 3: 33},
        ],
    )
    def test_key_builder_from_dict_with_valid_args(self, ctx, cose_key):
        try:
            ctx.from_dict(cose_key)
        except Exception:
            pytest.fail("from_dict should not fail.")

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
            ({1: 4, 3: 0}, "Unsupported or unknown alg(3): 0."),
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
