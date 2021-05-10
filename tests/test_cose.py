# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import base64
import datetime

import cbor2
import pytest
from cbor2 import CBORTag

import cwt
from cwt import COSE, EncodeError, Recipient, cose_key

from .utils import key_path


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return COSE(options={"kid_auto_inclusion": False})


class TestCOSE:
    """
    Tests for COSE.
    """

    def test_cose_constructor_with_options(self):
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})
        assert isinstance(ctx, COSE)

    def test_cose_encode_and_decode_with_options(self):
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})

        # MAC0
        mac_key = cose_key.from_symmetric_key(alg="HS256", kid="01")
        token = ctx.encode_and_mac(b"Hello world!", mac_key)
        assert b"Hello world!" == ctx.decode(token, mac_key)

        # MAC
        token = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            recipients=[Recipient(unprotected={1: -6, 4: b"01"})],
        )
        assert b"Hello world!" == ctx.decode(token, mac_key)

        # Encrypt0
        enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        token = ctx.encode_and_encrypt(b"Hello world!", enc_key)
        assert b"Hello world!" == ctx.decode(token, enc_key)

        # Encrypt
        token = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            recipients=[Recipient(unprotected={1: -6, 4: b"02"})],
        )
        assert b"Hello world!" == ctx.decode(token, enc_key)

        # Signature1
        sig_key = cose_key.from_jwk(
            {
                "kty": "EC",
                "kid": "03",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        token = ctx.encode_and_sign(b"Hello world!", sig_key)
        assert b"Hello world!" == ctx.decode(token, sig_key)

    def test_cose_encode_and_decode_with_protected_bytes(self):
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})

        # MAC0
        mac_key = cose_key.from_symmetric_key(alg="HS256", kid="01")
        token = ctx.encode_and_mac(b"Hello world!", mac_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(token, mac_key)

        # MAC
        token = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected=b"a0",
            recipients=[Recipient(unprotected={1: -6, 4: b"01"})],
        )
        assert b"Hello world!" == ctx.decode(token, mac_key)

        # Encrypt0
        enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        token = ctx.encode_and_encrypt(b"Hello world!", enc_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(token, enc_key)

        # Encrypt
        token = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected=b"a0",
            recipients=[Recipient(unprotected={1: -6, 4: b"02"})],
        )
        assert b"Hello world!" == ctx.decode(token, enc_key)

        # Signature1
        sig_key = cose_key.from_jwk(
            {
                "kty": "EC",
                "kid": "03",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        token = ctx.encode_and_sign(b"Hello world!", sig_key, protected=b"a0")
        assert b"Hello world!" == ctx.decode(token, sig_key)

    def test_cose_constructor_with_invalid_kid_auto_inclusion(self):
        with pytest.raises(ValueError) as err:
            COSE(options={"kid_auto_inclusion": "xxx"})
            pytest.fail("COSE should fail.")
        assert "kid_auto_inclusion should be bool." in str(err.value)

    def test_cose_constructor_with_invalid_alg_auto_inclusion(self):
        with pytest.raises(ValueError) as err:
            COSE(options={"alg_auto_inclusion": "xxx"})
            pytest.fail("COSE should fail.")
        assert "alg_auto_inclusion should be bool." in str(err.value)

    def test_cose_sample_cose_wg_examples_hmac_01(self, ctx):
        cwt_str = "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"
        key = cose_key.from_jwk(
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": "our-secret",
                "use": "sig",
                "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            }
        )
        token = ctx.encode_and_mac(
            b"This is the content.",
            key=key,
            recipients=[Recipient(unprotected={1: -6, 4: b"our-secret"})],
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_sign1_pass_01(self):
        key = cose_key.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})
        token = ctx.encode_and_sign(
            b"This is the content.",
            key,
            protected=bytes.fromhex("a0"),
            unprotected={1: -7, 4: b"11"},
        )
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_sign_pass_01(self):
        key = cose_key.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})
        token = ctx.encode_and_sign(
            b"This is the content.",
            [key],
            protected=bytes.fromhex("a0"),
        )
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_eddsa_01(self):
        cwt_str = "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106"
        key = cose_key.from_jwk(
            {
                "kty": "OKP",
                "kid": "11",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})
        token = ctx.encode_and_sign(
            b"This is the content.",
            [key],
            protected={3: 0},
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_eddsa_02(self):
        cwt_str = "D8628440A054546869732069732074686520636F6E74656E742E818343A10127A1044565643434385872ABF04F4BC7DFACF70C20C34A3CFBD27719911DC8518B2D67BF6AF62895D0FA1E6A1CB8B47AD1297C0E9C34BEB34E50DFFEF14350EBD57842807D54914111150F698543B0A5E1DA1DB79632C6415CE18EF74EDAEA680B0C8881439D869171481D78E2F7D26340C293C2ECDED8DE1425851900"
        key = cose_key.from_jwk(
            {
                "kty": "OKP",
                "kid": "ed448",
                "crv": "Ed448",
                "x": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE(options={"kid_auto_inclusion": False, "alg_auto_inclusion": False})
        token = ctx.encode_and_sign(
            b"This is the content.",
            [key],
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_eddsa_sig_01(self):
        cwt_str = "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D"
        key = cose_key.from_jwk(
            {
                "kty": "OKP",
                "kid": "11",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE(options={"alg_auto_inclusion": False})
        token = ctx.encode_and_sign(
            b"This is the content.",
            key,
            protected={1: -8, 3: 0},
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_eddsa_sig_02(self):
        cwt_str = "D28443A10127A10445656434343854546869732069732074686520636F6E74656E742E5872988240A3A2F189BD486DE14AA77F54686C576A09F2E7ED9BAE910DF9139C2AC3BE7C27B7E10A20FA17C9D57D3510A2CF1F634BC0345AB9BE00849842171D1E9E98B2674C0E38BFCF6C557A1692B01B71015A47AC9F7748840CAD1DA80CBB5B349309FEBB912672B377C8B2072AF1598B3700"
        key = cose_key.from_jwk(
            {
                "kty": "OKP",
                "kid": "ed448",
                "crv": "Ed448",
                "x": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(
                    bytes.fromhex(
                        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
                    )
                )
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE()
        token = ctx.encode_and_sign(
            b"This is the content.",
            key,
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_aes_ccm_01(self, ctx):
        cwt_str = "D8608443A1010AA1054D89F52F65A1C580933B5261A72F581C6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE818340A20125044A6F75722D73656372657440"
        key = cose_key.from_jwk(
            {
                "kty": "oct",
                "alg": "AES-CCM-16-64-128",
                "kid": "our-secret",
                "use": "enc",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            }
        )
        token = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            nonce=bytes.fromhex("89F52F65A1C580933B5261A72F"),
            recipients=[Recipient(unprotected={1: -6, 4: b"our-secret"})],
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_aes_gcm_01(self, ctx):
        cwt_str = "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73656372657440"
        key = cose_key.from_jwk(
            {
                "kty": "oct",
                "alg": "A128GCM",
                "kid": "our-secret",
                "use": "enc",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            }
        )
        token = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            nonce=bytes.fromhex("02D1F7E6F26C43D4868D87CE"),
            recipients=[Recipient(unprotected={1: -6, 4: b"our-secret"})],
        )
        assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_chacha_poly_01(self, ctx):
        # cwt_str = "D8608444A1011818A1054C26682306D4FB28CA01B43B8058245F2BD5381BBB04921A8477E55C0D850069674A05E683D416583AA0CEE0E2929CDF648094818340A2012504477365632D32353640"
        key = cose_key.from_jwk(
            {
                "kty": "oct",
                "alg": "ChaCha20/Poly1305",
                "kid": "sec-256",
                "use": "enc",
                "k": "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA",
            }
        )
        token = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            nonce=bytes.fromhex("26682306D4FB28CA01B43B80"),
            recipients=[Recipient(unprotected={1: -6, 4: b"sec-256"})],
        )
        # assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_sample_cose_wg_examples_chacha_poly_enc_01(self, ctx):
        # cwt_str = "D08344A1011818A1054C5C3A9950BD2852F66E6C8D4F58243E536D4992A21591575C55FA22981B31AE1C045946D0E41A8A1ABD12BC9525922F4EB618"
        key = cose_key.from_jwk(
            {
                "kty": "oct",
                "alg": "ChaCha20/Poly1305",
                "kid": "sec-256",
                "use": "enc",
                "k": "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA",
            }
        )
        token = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            nonce=bytes.fromhex("5C3A9950BD2852F66E6C8D4F"),
        )
        # assert token == bytes.fromhex(cwt_str)
        assert ctx.decode(token, key) == b"This is the content."

    def test_cose_encode_and_mac_with_recipient_has_unsupported_alg(self, ctx):
        key = cose_key.from_symmetric_key(alg="HS256")
        with pytest.raises(NotImplementedError) as err:
            ctx.encode_and_mac(
                b"This is the content.",
                key,
                recipients=[Recipient(unprotected={1: 0, 4: b"our-secret"})],
            )
            pytest.fail("encode_and_mac should fail.")
        assert "Algorithms other than direct are not supported for recipients." in str(
            err.value
        )

    def test_cose_encode_and_encrypt_with_recipient_has_unsupported_alg(self, ctx):
        key = cose_key.from_jwk(
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
                recipients=[Recipient(unprotected={1: 0, 4: b"our-secret"})],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "Algorithms other than direct are not supported for recipients." in str(
            err.value
        )

    def test_cose_encode_and_mac_with_invalid_payload(self, ctx):
        key = cose_key.from_symmetric_key(alg="HS256")
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
                "Invalid Signature format.",
            ),
            (
                cbor2.dumps(CBORTag(98, [b"", b"", b"", [b""]])),
                "Invalid Signature format.",
            ),
        ],
    )
    def test_cose_decode_with_invalid_data(self, ctx, invalid, msg):
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read(), kid="01")

        with pytest.raises(ValueError) as err:
            ctx.decode(invalid, public_key)
            pytest.fail("decode should fail.")
        assert msg in str(err.value)

    def test_cose_decode_mac0_with_invalid_multiple_keys(self, ctx):
        key1 = cose_key.from_symmetric_key(alg="HS256")
        key2 = cose_key.from_symmetric_key(alg="HS256")
        encoded = cwt.encode({"iss": "coap://as.example"}, key1)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not specified." in str(err.value)

    def test_cose_decode_encrypt0_with_invalid_multiple_keys(self, ctx):
        key1 = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
        key2 = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
        encoded = cwt.encode({"iss": "coap://as.example"}, key1)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not specified." in str(err.value)

    def test_cose_decode_signature1_with_invalid_multiple_keys(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = cose_key.from_pem(key_file.read())
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = cose_key.from_pem(key_file.read())
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read())
        encoded = cwt.encode({"iss": "coap://as.example"}, private_key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not specified." in str(err.value)

    def test_cose_decode_with_key_not_found(self, ctx):
        with open(key_path("public_key_es256.pem")) as key_file:
            key1 = cose_key.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            key2 = cose_key.from_pem(key_file.read(), kid="02")
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read(), kid="03")
        encoded = cwt.encode({"iss": "coap://as.example"}, private_key)
        with pytest.raises(ValueError) as err:
            ctx.decode(encoded, [key1, key2])
            pytest.fail("decode should fail.")
        assert "key is not specified." in str(err.value)
