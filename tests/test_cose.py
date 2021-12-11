# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import base64
import datetime
from secrets import token_bytes

import cbor2
import pytest
from cbor2 import CBORTag

import cwt
from cwt import COSE, COSEKey, DecodeError, EncodeError, Recipient, VerifyError
from cwt.recipient_interface import RecipientInterface
from cwt.signer import Signer

from .utils import key_path


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return COSE.new(alg_auto_inclusion=True)


class TestCOSE:
    """
    Tests for COSE.
    """

    def test_cose_constructor_with_options(self):
        ctx = COSE.new()
        assert isinstance(ctx, COSE)

    def test_cose_alg_auto_inclusion(self):
        ctx = COSE.new()
        ctx.alg_auto_inclusion = True
        assert ctx.alg_auto_inclusion is True

    def test_cose_kid_auto_inclusion(self):
        ctx = COSE.new()
        ctx.kid_auto_inclusion = True
        assert ctx.kid_auto_inclusion is True

    def test_cose_verify_kid(self):
        ctx = COSE.new()
        ctx.verify_kid = True
        assert ctx.verify_kid is True

    def test_cose_encode_and_decode_mac0_with_options(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)

        # MAC0
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_encode_and_decode_mac_with_options(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)

        # MAC
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        encoded = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            recipients=[RecipientInterface(unprotected={1: -6, 4: b"01"})],
        )
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_encode_and_decode_encrypt0_with_options(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)

        # Encrypt0
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key)
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

    def test_cose_encode_and_decode_encrypt_with_options(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)

        # Encrypt
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        rec = Recipient.from_jwk({"alg": "direct", "kid": "02"})
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            recipients=[rec],
        )
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

    def test_cose_encode_and_decode_signature1_with_options(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)

        # Signature1
        sig_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "03",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        encoded = ctx.encode_and_sign(b"Hello world!", sig_key)
        assert b"Hello world!" == ctx.decode(encoded, sig_key)

    def test_cose_encode_and_decode_mac0_with_protected_bytes(self):
        ctx = COSE.new(kid_auto_inclusion=True)

        # MAC0
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_encode_and_decode_mac_with_protected_bytes(self):
        ctx = COSE.new()

        # MAC
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        encoded = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected=b"a0",
            recipients=[RecipientInterface(unprotected={1: -6, 4: b"01"})],
        )
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_encode_and_decode_encrypt0_with_protected_bytes(self):
        ctx = COSE.new(kid_auto_inclusion=True)

        # Encrypt0
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

    def test_cose_encode_and_decode_encrypt_with_protected_bytes(self):
        ctx = COSE.new(kid_auto_inclusion=True)

        # Encrypt
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected=b"a0",
            recipients=[RecipientInterface(unprotected={1: -6, 4: b"02"})],
        )
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

    def test_cose_encode_and_decode_signature1_with_protected_bytes(self):
        ctx = COSE.new(kid_auto_inclusion=True)

        # Signature1
        sig_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "03",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        encoded = ctx.encode_and_sign(b"Hello world!", sig_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(encoded, sig_key)

    def test_cose_encode_and_decode_mac0_with_verify_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True, verify_kid=True)

        # MAC0
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_encode_and_decode_mac0_without_kid_with_verify_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True, verify_kid=True)

        # MAC0
        mac_key = COSEKey.from_symmetric_key(alg="HS256")
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, mac_key)
            pytest.fail("decode() should fail.")
        assert "kid should be specified." in str(err.value)

    def test_cose_encode_and_decode_with_recipient_builder(self):
        ctx = COSE.new()

        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        recipient = Recipient.from_jwk(
            {
                "alg": "direct",
                "kid": "01",
            }
        )
        encoded = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            recipients=[recipient],
        )
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

    def test_cose_constructor_with_invalid_kid_auto_inclusion(self):
        with pytest.raises(ValueError) as err:
            COSE.new(kid_auto_inclusion="xxx")
            pytest.fail("COSE() should fail.")
        assert "kid_auto_inclusion should be bool." in str(err.value)

    def test_cose_constructor_with_invalid_alg_auto_inclusion(self):
        with pytest.raises(ValueError) as err:
            COSE.new(alg_auto_inclusion="xxx")
            pytest.fail("COSE() should fail.")
        assert "alg_auto_inclusion should be bool." in str(err.value)

    def test_cose_constructor_with_invalid_verify_kid(self):
        with pytest.raises(ValueError) as err:
            COSE.new(verify_kid="xxx")
            pytest.fail("COSE() should fail.")
        assert "verify_kid should be bool." in str(err.value)

    def test_cose_constructor_with_invalid_ca_certs(self):
        with pytest.raises(ValueError) as err:
            COSE.new(ca_certs=b"xxx")
            pytest.fail("COSE() should fail.")
        assert "ca_certs should be str." in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {"xxx": "yyy"},
                "Unsupported or unknown COSE header parameter: xxx.",
            ),
            (
                {"alg": "xxx"},
                "Unsupported or unknown alg: xxx.",
            ),
        ],
    )
    def test_cose_encode_and_mac_with_invalid_protected(self, ctx, invalid, msg):
        key = COSEKey.from_symmetric_key(alg="HS256")
        with pytest.raises(ValueError) as err:
            ctx.encode_and_mac(b"This is the content.", key, protected=invalid)
            pytest.fail("encode_and_mac should fail.")
        assert msg in str(err.value)

    def test_cose_encode_and_mac_with_recipient_has_unsupported_alg(self, ctx):
        key = COSEKey.from_symmetric_key(alg="HS256")
        with pytest.raises(NotImplementedError) as err:
            ctx.encode_and_mac(
                b"This is the content.",
                key,
                recipients=[RecipientInterface(unprotected={1: 0, 4: b"our-secret"})],
            )
            pytest.fail("encode_and_mac should fail.")
        assert "Algorithms other than direct are not supported for recipients." in str(err.value)

    def test_cose_encode_and_encrypt_with_recipient_has_unsupported_alg(self, ctx):
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "AES-CCM-16-64-128",
                "kid": "our-secret",
                "use": "enc",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            }
        )
        with pytest.raises(NotImplementedError) as err:
            ctx.encode_and_encrypt(
                b"This is the content.",
                key,
                nonce=bytes.fromhex("89F52F65A1C580933B5261A72F"),
                recipients=[RecipientInterface(unprotected={1: 0, 4: b"our-secret"})],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "Algorithms other than direct are not supported for recipients." in str(err.value)

    def test_cose_encode_and_mac_with_invalid_payload(self, ctx):
        key = COSEKey.from_symmetric_key(alg="HS256")
        with pytest.raises(EncodeError) as err:
            ctx.encode_and_mac(datetime.datetime.now(), key, {}, {})
            pytest.fail("encode_and_mac should fail.")
        assert "Failed to encode." in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                "invalid_string_data",
                "Invalid COSE format.",
            ),
            (
                {},
                "Invalid COSE format.",
            ),
            (
                [],
                "Invalid COSE format.",
            ),
            (
                123,
                "Invalid COSE format.",
            ),
            (
                cbor2.CBORTag(16, "invalid_string_data"),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, {}),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, []),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, 123),
                "Invalid Encrypt0 format.",
            ),
            (
                cbor2.CBORTag(16, [b"", b"invalid byte data", b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", "invalid string data", b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", [], b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(16, [b"", 123, b""]),
                "unprotected header should be dict.",
            ),
            (
                cbor2.dumps(CBORTag(96, [])),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, {})),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, b"")),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, 123)),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, [b"", b"", b""])),
                "Invalid Encrypt format.",
            ),
            (
                cbor2.dumps(CBORTag(96, [b"", b"", b"", [b""]])),
                "unprotected header should be dict.",
            ),
            (
                cbor2.CBORTag(17, "invalid_string_data"),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, {}),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, []),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(17, 123),
                "Invalid MAC0 format.",
            ),
            (
                cbor2.CBORTag(97, "invalid_string_data"),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, {}),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, []),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(97, 123),
                "Invalid MAC format.",
            ),
            (
                cbor2.CBORTag(18, "invalid_string_data"),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, {}),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, []),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.CBORTag(18, 123),
                "Invalid Signature1 format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [])),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, {})),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, b"")),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, 123)),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", b"", b"", b""])),
                "unprotected header should be dict.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", b"", b"", [b""]])),
                "unprotected header should be dict.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", {}, b"", b""])),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", {}, b"", [b""]])),
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", {}, b"", [[b"", b"", b""]]])),
                "unprotected header in signature structure should be dict.",
            ),
        ],
    )
    def test_cose_decode_with_invalid_data(self, ctx, invalid, msg):
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        with pytest.raises(ValueError) as err:
            ctx.decode(invalid, public_key)
            pytest.fail("decode should fail.")
        assert msg in str(err.value)

    def test_cose_decode_mac0_without_key_and_materials(self, ctx):
        key = COSEKey.from_symmetric_key(alg="HS256")
        encoded = cwt.encode({"iss": "coap://as.example"}, key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, b"")
            pytest.fail("decode should fail.")
        assert "key in keys should have COSEKeyInterface." in str(err.value)

    def test_cose_decode_mac0_with_multiple_keys_without_kid(self, ctx):
        key1 = COSEKey.from_symmetric_key(alg="HS256")
        key2 = COSEKey.from_symmetric_key(alg="HS256")
        encoded = ctx.encode_and_mac(b"Hello world!", key1)
        decoded = ctx.decode(encoded, [key1, key2])
        assert decoded == b"Hello world!"

    def test_cose_decode_mac0_with_different_multiple_keys(self, ctx):
        key1 = COSEKey.from_symmetric_key(alg="HS256")
        key2 = COSEKey.from_symmetric_key(alg="HS256")
        key3 = COSEKey.from_symmetric_key(alg="HS256")
        encoded = ctx.encode_and_mac(b"Hello world!", key1)
        with pytest.raises(VerifyError) as err:
            ctx.decode(encoded, [key2, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to compare digest." in str(err.value)

    def test_cose_decode_mac0_with_different_multiple_keys_2(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        key1 = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        key2 = COSEKey.from_symmetric_key(alg="HS256")
        key3 = COSEKey.from_symmetric_key(alg="HS256")
        encoded = ctx.encode_and_mac(b"Hello world!", key1)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key2, key3])
            pytest.fail("decode() should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_mac0_with_multiple_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        key1 = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        key2 = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        key3 = COSEKey.from_symmetric_key(alg="HS256", kid="02")
        encoded = ctx.encode_and_mac(b"Hello world!", key2)
        assert b"Hello world!" == ctx.decode(encoded, [key1, key2, key3])

    def test_cose_decode_mac_with_multiple_keys_without_kid(self, ctx):
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r1 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        r2 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material2})
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material3})
        assert b"Hello world!" == ctx.decode(encoded, keys=[shared_key3, shared_key1])

    def test_cose_decode_mac_with_multiple_keys_with_verify_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r1 = Recipient.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        r2 = Recipient.from_jwk({"kid": "02", "kty": "oct", "alg": "A128KW", "k": material2})
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material3})

        assert b"Hello world!" == ctx.decode(encoded, keys=[shared_key3, shared_key1])

    def test_cose_decode_mac_with_multiple_keys_with_verify_kid_and_protected_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        shared_key1 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        shared_key2 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material2})
        shared_key3 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material3})

        r1 = Recipient.new(protected={1: -3, 4: b"01"}, sender_key=shared_key1)
        r2 = Recipient.new(protected={1: -3, 4: b"02"}, sender_key=shared_key2)
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material3})

        assert b"Hello world!" == ctx.decode(encoded, keys=[shared_key3, shared_key1])

    def test_cose_decode_mac_with_multiple_keys_without_kid_with_verify_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r1 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        r2 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material2})
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": material3})

        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, keys=[shared_key3, shared_key1])
            pytest.fail("decode() should fail.")
        assert "kid should be specified in recipient." in str(err.value)

    def test_cose_decode_mac_with_multiple_keys_without_recipient_kid_with_verify_kid(
        self,
    ):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r1 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material1})
        r2 = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "k": material2})
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "02", "kty": "oct", "alg": "A128KW", "k": material3})

        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, keys=[shared_key3, shared_key1])
            pytest.fail("decode() should fail.")
        assert "kid should be specified in recipient." in str(err.value)

    def test_cose_decode_mac_with_different_multiple_keys(self, ctx):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r2 = Recipient.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material2})
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material3})

        with pytest.raises(DecodeError) as err:
            ctx.decode(encoded, keys=[shared_key1, shared_key3])
            pytest.fail("decode() should fail.")
        assert "Failed to decode key." in str(err.value)

    def test_cose_decode_mac_with_different_multiple_keys_2(self):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="HS256")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r2 = Recipient.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material2})
        r2.apply(key)

        encoded = ctx.encode_and_mac(b"Hello world!", key, recipients=[r2])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "02", "kty": "oct", "alg": "A128KW", "k": material3})

        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, keys=[shared_key1, shared_key3])
            pytest.fail("decode() should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_mac_with_multiple_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        key1 = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        key2 = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        key3 = COSEKey.from_symmetric_key(alg="HS256", kid="02")
        encoded = ctx.encode_and_mac(b"Hello world!", key2)
        decoded = ctx.decode(encoded, [key1, key2, key3])
        assert decoded == b"Hello world!"

    def test_cose_decode_encrypt0_with_multiple_keys_without_kid(self, ctx):
        key1 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        key2 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        encoded = ctx.encode_and_encrypt(b"Hello world!", key1)
        decoded = ctx.decode(encoded, [key2, key1])
        assert decoded == b"Hello world!"

    def test_cose_decode_encrypt0_with_different_multiple_keys(self, ctx):
        key1 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        key2 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        key3 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        encoded = ctx.encode_and_encrypt(b"Hello world!", key1)
        with pytest.raises(DecodeError) as err:
            ctx.decode(encoded, [key2, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_cose_decode_encrypt0_with_different_multiple_keys_2(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        key1 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        key2 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        key3 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
        encoded = ctx.encode_and_encrypt(b"Hello world!", key1)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key2, key3])
            pytest.fail("decode() should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_encrypt0_with_multiple_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        key1 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        key2 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        key3 = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        encoded = ctx.encode_and_encrypt(b"Hello world!", key2)
        decoded = ctx.decode(encoded, [key1, key2, key3])
        assert decoded == b"Hello world!"

    def test_cose_decode_encrypt_with_multiple_keys_with_verify_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, verify_kid=True)
        key = COSEKey.from_symmetric_key(alg="A128GCM")

        material1 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material2 = base64.urlsafe_b64encode(token_bytes(16)).decode()
        material3 = base64.urlsafe_b64encode(token_bytes(16)).decode()

        r1 = Recipient.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        r2 = Recipient.from_jwk({"kid": "02", "kty": "oct", "alg": "A128KW", "k": material2})
        r1.apply(key)
        r2.apply(key)

        encoded = ctx.encode_and_encrypt(b"Hello world!", key, recipients=[r2, r1])

        shared_key1 = COSEKey.from_jwk({"kid": "01", "kty": "oct", "alg": "A128KW", "k": material1})
        shared_key3 = COSEKey.from_jwk({"kid": "03", "kty": "oct", "alg": "A128KW", "k": material3})

        assert b"Hello world!" == ctx.decode(encoded, keys=[shared_key3, shared_key1])

    def test_cose_decode_signature1_with_multiple_keys_without_kid(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        decoded = ctx.decode(encoded, [key1, key2])
        assert decoded == b"Hello world!"

    def test_cose_decode_signature1_with_ca_certs_without_kid(self):
        with open(key_path("cert_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_cert_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        ctx = COSE.new(alg_auto_inclusion=True, ca_certs=key_path("cacert.pem"))
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        decoded = ctx.decode(encoded, [public_key])
        assert decoded == b"Hello world!"

    def test_cose_decode_signature1_with_different_multiple_keys(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        # with open(key_path("public_key_ed25519.pem")) as key_file:
        #     key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        with pytest.raises(VerifyError) as err:
            ctx.decode(encoded, [key1, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_decode_signature1_with_different_multiple_keys_2(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        # with open(key_path("public_key_ed25519.pem")) as key_file:
        #     key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key3])
            pytest.fail("decode() should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_signature1_with_multiple_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        decoded = ctx.decode(encoded, [key1, key2, key3])
        assert decoded == b"Hello world!"

    def test_cose_decode_signature1_with_same_kid_bound_to_different_key(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read(), kid="03")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", private_key)
        with pytest.raises(VerifyError) as err:
            ctx.decode(encoded, [key1, key2, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_decode_signature1_with_key_not_found(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="03")
        encoded = cwt.encode({"iss": "coap://as.example"}, private_key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_signature_with_multiple_keys_without_kid(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read())
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        decoded = ctx.decode(encoded, [key1, key2])
        assert decoded == b"Hello world!"

    def test_cose_decode_signature_with_different_multiple_keys(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        # with open(key_path("public_key_ed25519.pem")) as key_file:
        #     key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read())
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        with pytest.raises(VerifyError) as err:
            ctx.decode(encoded, [key1, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_decode_signature_with_different_multiple_keys_2(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read())
        # with open(key_path("public_key_ed25519.pem")) as key_file:
        #     key2 = COSEKey.from_pem(key_file.read())
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key3])
            pytest.fail("decode() should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_signature_with_multiple_kid(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        decoded = ctx.decode(encoded, [key1, key2, key3])
        assert decoded == b"Hello world!"

    def test_cose_decode_signature_with_same_kid_bound_to_different_key(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("public_key_ed448.pem")) as key_file:
            key3 = COSEKey.from_pem(key_file.read(), kid="03")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read(), kid="01")
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        with pytest.raises(VerifyError) as err:
            ctx.decode(encoded, [key1, key2, key3])
            pytest.fail("decode() should fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_decode_signature_with_key_not_found(self):
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = COSEKey.from_pem(key_file.read(), kid="02")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            signer = Signer.from_pem(key_file.read(), kid="03")
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not found." in str(err.value)

    def test_cose_decode_ecdh_es_hkdf_256_without_context(self):
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        recipient = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+HKDF-256"})
        enc_key = recipient.apply(recipient_key=public_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key=enc_key,
            recipients=[recipient],
        )

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, private_key)
            pytest.fail("decode should fail.")
        assert "context should be set." in str(err.value)

    def test_cose_decode_ecdh_aes_key_wrap_without_context(self):
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        recipient = Recipient.from_jwk({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A128KW"})
        recipient.apply(enc_key, recipient_key=public_key, context={"alg": "A128GCM"})
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key=enc_key,
            recipients=[recipient],
        )

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, private_key)
            pytest.fail("decode should fail.")
        assert "context should be set." in str(err.value)
