# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for CWT.
"""
from secrets import token_bytes

# import cbor2
import pytest

from cwt import CWT, DecodeError, VerifyError, cose_key

from .utils import key_path, now


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return CWT()


class TestCWT:
    """
    Tests for CWT.
    """

    def test_cwt_constructor_without_args(self):
        """"""
        ctx = CWT()
        assert isinstance(ctx, CWT)
        assert ctx.expires_in == 3600
        assert ctx.leeway == 60

    def test_cwt_constructor_with_expires_in(self):
        """"""
        ctx = CWT(options={"expires_in": 7200})
        assert isinstance(ctx, CWT)
        assert ctx.expires_in == 7200

    def test_cwt_constructor_with_leeway(self):
        """"""
        ctx = CWT(options={"leeway": 10})
        assert isinstance(ctx, CWT)
        assert ctx.leeway == 10

    @pytest.mark.parametrize(
        "invalid",
        [
            {"expires_in": "xxx"},
            {"expires_in": -1},
            {"leeway": "xxx"},
            {"leeway": -1},
        ],
    )
    def test_cwt_constructor_with_invalid_args(self, invalid):
        """"""
        with pytest.raises(ValueError) as err:
            CWT(options=invalid)
            pytest.fail("CWT() should be fail.")
        assert "should be" in str(err.value)

    def test_cwt_encode_and_mac_with_default_alg(self, ctx):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 4 in decoded and isinstance(decoded[4], int)
        assert 5 in decoded and isinstance(decoded[5], int)
        assert 6 in decoded and isinstance(decoded[6], int)
        assert decoded[5] == decoded[6]
        assert decoded[4] == decoded[5] + ctx.expires_in
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "invalid",
        [
            {-260: "wrong_type"},
            {-259: 123},
            {-258: 123},
            {-257: "wrong_type"},
            {1: 123},
            {2: 123},
            {3: 123},
            {4: "wrong_type"},
            {5: "wrong_type"},
            {6: "wrong_type"},
            {7: 123},
            {8: 123},
        ],
    )
    def test_cwt_encode_and_mac_with_invalid_args(self, ctx, invalid):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(invalid, key)
            pytest.fail("encode_and_mac should be fail.")
        assert "should be" in str(err.value)

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
        ],
    )
    def test_cwt_encode_and_mac_with_valid_alg_hmac(self, ctx, alg):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword", alg=alg)
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "alg, nonce, key",
        [
            ("AES-CCM-16-64-128", token_bytes(13), token_bytes(16)),
            ("AES-CCM-16-64-256", token_bytes(13), token_bytes(32)),
            ("AES-CCM-64-64-128", token_bytes(7), token_bytes(16)),
            ("AES-CCM-64-64-256", token_bytes(7), token_bytes(32)),
            ("AES-CCM-16-128-128", token_bytes(13), token_bytes(16)),
            ("AES-CCM-16-128-256", token_bytes(13), token_bytes(32)),
            ("AES-CCM-64-128-128", token_bytes(7), token_bytes(16)),
            ("AES-CCM-64-128-256", token_bytes(7), token_bytes(32)),
        ],
    )
    def test_cwt_encode_and_encrypt_with_valid_alg_aes_ccm(self, ctx, alg, nonce, key):
        """"""
        enc_key = cose_key.from_symmetric_key(key, alg=alg)
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=nonce,
        )
        decoded = ctx.decode(token, enc_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.pem", "public_key_ed25519.pem"),
            ("private_key_ed448.pem", "public_key_ed448.pem"),
            ("private_key_es256.pem", "public_key_es256.pem"),
            ("private_key_es256k.pem", "public_key_es256k.pem"),
            ("private_key_es384.pem", "public_key_es384.pem"),
            ("private_key_es512.pem", "public_key_es512.pem"),
            # ("private_key_x25519.pem", "public_key_x25519.pem"),
            # ("private_key_x448.pem", "public_key_x448.pem"),
        ],
    )
    def test_cwt_encode_and_sign_with_valid_alg(
        self, ctx, private_key_path, public_key_path
    ):
        """"""
        with open(key_path(private_key_path)) as key_file:
            private_key = cose_key.from_pem(key_file.read())
        with open(key_path(public_key_path)) as key_file:
            public_key = cose_key.from_pem(key_file.read())
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            private_key,
        )
        decoded = ctx.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_encrypt_with_invalid_nonce(self, ctx):
        """"""
        enc_key = cose_key.from_symmetric_key(token_bytes(16), alg="AES-CCM-16-64-128")
        with pytest.raises(ValueError) as err:
            res = ctx.encode_and_encrypt(
                {1: "https://as.example", 2: "someone", 7: b"123"},
                enc_key,
                nonce=token_bytes(7),  # should be 13
            )
            pytest.fail("encode_and_encrypt should be fail: res=%s" % vars(res))
        assert "The length of nonce should be" in str(err.value)

    def test_cwt_decode_with_invalid_mac_key(self, ctx):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        wrong_key = cose_key.from_symmetric_key("xxxxxxxxxx")
        with pytest.raises(VerifyError) as err:
            res = ctx.decode(token, wrong_key)
            pytest.fail("decode should be fail: res=%s" % vars(res))
        assert "Failed to compare digest" in str(err.value)

    def test_cwt_decode_with_invalid_enc_key(self, ctx):
        """"""
        enc_key = cose_key.from_symmetric_key(token_bytes(16), alg="AES-CCM-16-64-128")
        wrong_key = cose_key.from_symmetric_key(
            token_bytes(16), alg="AES-CCM-16-64-128"
        )
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=token_bytes(13),
        )
        with pytest.raises(DecodeError) as err:
            ctx.decode(token, wrong_key)
            pytest.fail("decode should be fail.")
        assert "Failed to decrypt" in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: "https://as.example", 2: "a", 4: now() - 100, 5: now(), 6: now()},
                "The token has expired.",
            ),
            (
                {
                    1: "https://as.example",
                    2: "a",
                    4: now() + 100,
                    5: now() + 100,
                    6: now(),
                },
                "The token is not yet valid.",
            ),
        ],
    )
    def test_cwt_decode_with_invalid_claim(self, ctx, invalid, msg):
        """"""
        mac_key = cose_key.from_symmetric_key("mysecretpassword")
        token = ctx.encode_and_mac(invalid, mac_key)
        with pytest.raises(VerifyError) as err:
            ctx.decode(token, mac_key)
            pytest.fail("decode should be fail.")
        assert msg in str(err.value)
