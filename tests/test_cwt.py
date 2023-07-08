# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for CWT.
"""
from secrets import token_bytes

import cbor2
import pytest
from cbor2 import CBORTag, dumps

from cwt import COSE, CWT, Claims, COSEKey, DecodeError, Recipient, VerifyError
from cwt.cose_key_interface import COSEKeyInterface
from cwt.signer import Signer

from .utils import key_path, now


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return CWT.new()


class TestCWT:
    """
    Tests for CWT.
    """

    def test_cwt_constructor_without_args(self):
        ctx = CWT.new()
        assert isinstance(ctx, CWT)
        assert ctx.expires_in == 3600
        assert ctx.leeway == 60

    def test_cwt_constructor_with_expires_in(self):
        ctx = CWT.new(expires_in=7200)
        assert isinstance(ctx, CWT)
        assert ctx.expires_in == 7200

    def test_cwt_constructor_with_leeway(self):
        ctx = CWT.new(leeway=10)
        assert isinstance(ctx, CWT)
        assert ctx.leeway == 10

    @pytest.mark.parametrize(
        "invalid",
        [
            "xxx",
            0,
            -1,
        ],
    )
    def test_cwt_constructor_with_invalid_expires_in(self, invalid):
        with pytest.raises(ValueError) as err:
            CWT.new(expires_in=invalid)
            pytest.fail("CWT.new() should fail.")
        assert "should be" in str(err.value)

    @pytest.mark.parametrize(
        "invalid",
        [
            "xxx",
            0,
            -1,
        ],
    )
    def test_cwt_constructor_with_invalid_leeway(self, invalid):
        with pytest.raises(ValueError) as err:
            CWT.new(leeway=invalid)
            pytest.fail("CWT.new() should fail.")
        assert "should be" in str(err.value)

    def test_cwt_expires_in(self):
        ctx = CWT.new()
        ctx.expires_in = 7600
        assert ctx.expires_in == 7600

    def test_cwt_expires_in_with_0(self):
        ctx = CWT.new()
        with pytest.raises(ValueError) as err:
            ctx.expires_in = 0
            pytest.fail("expires_in should fail.")
        assert "expires_in should be positive number." in str(err.value)

    def test_cwt_expires_in_with_negative_value(self):
        ctx = CWT.new()
        with pytest.raises(ValueError) as err:
            ctx.expires_in = -1
            pytest.fail("expires_in should fail.")
        assert "expires_in should be positive number." in str(err.value)

    def test_cwt_leeway(self):
        ctx = CWT.new()
        ctx.leeway = 10
        assert ctx.leeway == 10

    def test_cwt_leeway_with_negative_value(self):
        ctx = CWT.new()
        with pytest.raises(ValueError) as err:
            ctx.leeway = -1
            pytest.fail("leeway should fail.")
        assert "leeway should be positive number." in str(err.value)

    def test_cwt_encode_with_claims_object(self, ctx):
        key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        token = ctx.encode(
            Claims.from_json({"iss": "https://as.example", "sub": "someone", "cti": b"123"}),
            key,
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "invalid_key",
        [
            COSEKeyInterface({1: 4, 2: b"123", 3: 1, 4: []}),
            COSEKeyInterface({1: 4, 2: b"123", 3: 1, 4: [1, 3]}),
            COSEKeyInterface({1: 4, 2: b"123", 3: 1, 4: [3, 9]}),
            COSEKeyInterface({1: 4, 2: b"123", 3: 1, 4: [9, 4]}),
        ],
    )
    def test_cwt_encode_with_invalid_key(self, ctx, invalid_key):
        with pytest.raises(ValueError) as err:
            ctx.encode({1: "https://as.example", 2: "someone", 7: b"123"}, invalid_key)
            pytest.fail("CWT.new() should fail.")
        assert "The key operation could not be specified." in str(err.value)

    def test_cwt_encode_and_mac_with_default_alg(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HS256", kid="01")
        token = ctx.encode_and_mac({1: "https://as.example", 2: "someone", 7: b"123"}, key)
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
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
        ],
    )
    def test_cwt_encode_and_mac_with_valid_alg_hmac(self, ctx, alg):
        key = COSEKey.from_symmetric_key("mysecret", alg=alg, kid="01")
        token = ctx.encode_and_mac({1: "https://as.example", 2: "someone", 7: b"123"}, key)
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_mac_with_tagged(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="01")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            key,
            tagged=True,
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_mac_with_recipient(self, ctx):
        recipient = Recipient.new(unprotected={1: -6, 4: b"our-secret"})
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="our-secret")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            key,
            tagged=True,
            recipients=[recipient],
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_mac_with_empty_recipient(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="01")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            key,
            tagged=True,
            recipients=[],
        )
        decoded = ctx.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
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
            {3: [123, 456]},
            {3: ["coaps://rs1.example", 456]},
            {4: "wrong_type"},
            {5: "wrong_type"},
            {6: "wrong_type"},
            {7: 123},
            {8: 123},
        ],
    )
    def test_cwt_encode_and_mac_with_invalid_args(self, ctx, invalid):
        key = COSEKey.from_symmetric_key("mysecret", alg="HS256")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(invalid, key)
            pytest.fail("encode_and_mac should fail.")
        assert "should be" in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: "https://as.example", 2: "someone", 7: b"123", 4: "exp"},
                "exp(4) should be int or float.",
            ),
            (
                {1: "https://as.example", 2: "someone", 7: b"123", 5: "nbf"},
                "nbf(5) should be int or float.",
            ),
        ],
    )
    def test_cwt_encode_and_mac_with_invalid_claims(self, ctx, invalid, msg):
        key = COSEKey.from_symmetric_key("mysecret", alg="HS256")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(invalid, key)
            pytest.fail("encode_and_mac should fail.")
        assert msg in str(err.value)

    def test_cwt_encode_and_mac_with_invalid_cbor_format(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(
                b'{1: "https://as.example", 2: "someone", 7: "123"',
                key,
            )
            pytest.fail("encode_and_mac should fail.")
        assert "Invalid claim format." in str(err.value)

    def test_cwt_encode_and_mac_with_untagged_cbor_bytes(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(
                cbor2.dumps({1: "https://as.example", 2: "someone", 7: "123"}),
                key,
            )
            pytest.fail("encode_and_mac should fail.")
        assert "A bytes-formatted claims needs CBOR(COSE) Tag." in str(err.value)

    def test_cwt_encode_and_mac_with_invalid_tagged_cwt(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            key,
        )
        tagged_token = cbor2.dumps(CBORTag(62, token))
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(tagged_token, key)
            pytest.fail("encode_and_mac should fail.")
        assert "Unsupported or unknown CBOR tag(62)." in str(err.value)

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
        enc_key = COSEKey.from_symmetric_key(key, alg=alg, kid="01")
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=nonce,
        )
        decoded = ctx.decode(token, enc_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_encrypt_with_invalid_key_and_without_nonce(self, ctx):
        enc_key = COSEKey.from_symmetric_key(alg="HMAC 256/64", kid="01")
        # enc_key = COSEKey.generate_symmetric_key(alg="A128GCM", kid="01")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_encrypt(
                {1: "https://as.example", 2: "someone", 7: b"123"},
                enc_key,
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "The COSE message is not suitable for COSE Encrypt0/Encrypt." in str(err.value)

    @pytest.mark.parametrize(
        "alg",
        [
            "A128GCM",
            "A192GCM",
            "A256GCM",
            "ChaCha20/Poly1305",
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
    def test_cwt_encode_and_encrypt_without_key_and_nonce(self, ctx, alg):
        enc_key = COSEKey.from_symmetric_key(alg=alg, kid="01")
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
        )
        decoded = ctx.decode(token, enc_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "alg, key",
        [
            ("A128GCM", token_bytes(16)),
            ("A192GCM", token_bytes(24)),
            ("A256GCM", token_bytes(32)),
        ],
    )
    def test_cwt_encode_and_encrypt_with_valid_alg_aes_gcm(self, ctx, alg, key):
        enc_key = COSEKey.from_symmetric_key(key, alg=alg, kid="01")
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=token_bytes(12),
        )
        decoded = ctx.decode(token, enc_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_encrypt_with_tagged(self, ctx):
        key = token_bytes(16)
        nonce = token_bytes(13)
        enc_key = COSEKey.from_symmetric_key(key, alg="AES-CCM-16-64-128", kid="01")
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=nonce,
            tagged=True,
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
    def test_cwt_encode_and_sign_with_valid_alg(self, ctx, private_key_path, public_key_path):
        with open(key_path(private_key_path)) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path(public_key_path)) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            private_key,
        )
        decoded = ctx.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "alg",
        [
            "PS256",
            "PS384",
            "PS512",
            "RS256",
            "RS384",
            "RS512",
            -37,
            -38,
            -39,
            -257,
            -258,
            -259,
        ],
    )
    def test_cwt_encode_and_sign_with_valid_alg_rsa(self, ctx, alg):
        with open(key_path("public_key_rsa.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), alg=alg, kid="01")
        with open(key_path("private_key_rsa.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg=alg, kid="01")
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            private_key,
        )
        decoded = ctx.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_sign_with_tagged(self, ctx):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            private_key,
            tagged=True,
        )
        decoded = ctx.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 7 in decoded and decoded[7] == b"123"

    def test_cwt_encode_and_sign_with_multiple_signatures(self, ctx):
        with open(key_path("private_key_es256.pem")) as key_file:
            signer_1 = Signer.from_pem(key_file.read(), kid="1")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key_1 = COSEKey.from_pem(key_file.read(), kid="1")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer_2 = Signer.from_pem(key_file.read(), kid="2")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key_2 = COSEKey.from_pem(key_file.read(), kid="2")
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            signers=[signer_1, signer_2],
        )
        decoded = ctx.decode(token, public_key_1)
        assert isinstance(decoded, dict)
        assert 1 in decoded and decoded[1] == "https://as.example"
        decoded = ctx.decode(token, public_key_2)
        assert isinstance(decoded, dict)
        assert 1 in decoded and decoded[1] == "https://as.example"

    def test_cwt_encode_and_encrypt_with_invalid_nonce(self, ctx):
        enc_key = COSEKey.from_symmetric_key(token_bytes(16), alg="AES-CCM-16-64-128")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_encrypt(
                {1: "https://as.example", 2: "someone", 7: b"123"},
                enc_key,
                nonce=token_bytes(7),  # should be 13
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "The length of nonce should be" in str(err.value)

    def test_cwt_encode_and_sign_with_signatures_kid_mismatch(self, ctx):
        with open(key_path("private_key_es256.pem")) as key_file:
            signer_1 = Signer.from_pem(key_file.read(), kid="1")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key_1 = COSEKey.from_pem(key_file.read(), kid="3")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer_2 = Signer.from_pem(key_file.read(), kid="2")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            COSEKey.from_pem(key_file.read(), kid="2")
        token = ctx.encode_and_sign(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            signers=[signer_1, signer_2],
        )
        with pytest.raises(ValueError) as err:
            ctx.decode(token, public_key_1)
            pytest.fail("decode should fail.")
        assert "key is not found." in str(err.value)

    def test_cwt_decode_with_invalid_mac_key(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HS256", kid="01")
        token = ctx.encode_and_mac({1: "https://as.example", 2: "someone", 7: b"123"}, key)
        wrong_key = COSEKey.from_symmetric_key("xxxxxxxxxx", alg="HS256", kid="01")
        with pytest.raises(VerifyError) as err:
            res = ctx.decode(token, wrong_key)
            pytest.fail("decode should fail: res=%s" % vars(res))
        assert "Failed to compare digest" in str(err.value)

    @pytest.mark.parametrize(
        "invalid",
        [
            b"Invalid data.",
            b"x",
            b"\x07\xf6o,n\x83\xc0r\x07A\xb6\xde.\xf7>A\xdf\xc7\xee\t",
        ],
    )
    def test_cwt_decode_with_invalid_cwt(self, ctx, invalid):
        key = COSEKey.from_symmetric_key(alg="AES-CCM-16-64-128")
        with pytest.raises(DecodeError) as err:
            ctx.decode(invalid, key)
            pytest.fail("decode should fail.")
        assert "Failed to decode." in str(err.value)

    def test_cwt_decode_with_invalid_enc_key(self, ctx):
        enc_key = COSEKey.from_symmetric_key(token_bytes(16), alg="AES-CCM-16-64-128", kid="01")
        wrong_key = COSEKey.from_symmetric_key(token_bytes(16), alg="AES-CCM-16-64-128", kid="01")
        token = ctx.encode_and_encrypt(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            enc_key,
            nonce=token_bytes(13),
        )
        with pytest.raises(DecodeError) as err:
            ctx.decode(token, wrong_key)
            pytest.fail("decode should fail.")
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
        mac_key = COSEKey.from_symmetric_key("mysecret", alg="HS256", kid="01")
        token = ctx.encode_and_mac(invalid, mac_key)
        with pytest.raises(VerifyError) as err:
            ctx.decode(token, mac_key)
            pytest.fail("decode should fail.")
        assert msg in str(err.value)

    def test_cwt_decode_with_invalid_tagged_cwt(self, ctx):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="01")
        token = ctx.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"},
            key,
        )
        tagged_token = cbor2.dumps(CBORTag(62, token))
        with pytest.raises(ValueError) as err:
            ctx.decode(tagged_token, key)
            pytest.fail("decode should fail.")
        assert "Unsupported or unknown CBOR tag(62)." in str(err.value)

    @pytest.mark.parametrize(
        "claims",
        [
            {1: "https://as.example", 2: "someone", 7: b"123", 4: now() + 100},
            {1: "https://as.example", 2: "someone", 7: b"123", 5: now() - 100},
        ],
    )
    def test_cwt__verify_with_valid_args(self, ctx, claims):
        try:
            ctx._verify(claims)
        except Exception:
            pytest.fail("_verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: "https://as.example", 2: "someone", 7: b"123", 4: "exp"},
                "exp should be int or float.",
            ),
            (
                {1: "https://as.example", 2: "someone", 7: b"123", 5: "nbf"},
                "nbf should be int or float.",
            ),
        ],
    )
    def test_cwt__verify_with_invalid_args(self, ctx, invalid, msg):
        with pytest.raises(ValueError) as err:
            ctx._verify(invalid)
            pytest.fail("_verify should fail.")
        assert msg in str(err.value)

    def test_cwt_decode_with_cwt_claims_in_headers(self, ctx):
        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        payload = dumps({1: "https://as.example", 2: "someone"})
        protected = {13: {1: "https://as.example"}}
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        cwt = cose.encode_and_mac(payload, mac_key, protected)
        decoded = ctx.decode(cwt, mac_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: "https://asx.example", 2: "someone"},
                "The CWT claim(1) value in protected header does not match the values in the payload.",
            ),
            (
                {1: "https://as.example", 2: "someonex"},
                "The CWT claim(2) value in protected header does not match the values in the payload.",
            ),
        ],
    )
    def test_cwt_decode_with_invalid_cwt_claims_in_headers(self, ctx, invalid, msg):
        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        payload = dumps({1: "https://as.example", 2: "someone"})
        protected = {13: invalid}
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        cwt = cose.encode_and_mac(payload, mac_key, protected)
        with pytest.raises(VerifyError) as err:
            ctx.decode(cwt, mac_key)
            pytest.fail("verify should fail.")
        assert msg in str(err.value)
