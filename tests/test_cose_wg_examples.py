# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSE.
"""

import base64

import cbor2
import pytest

from cwt import COSE, COSEKey, Recipient
from cwt.signer import Signer
from cwt.utils import base64url_decode


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return COSE.new(alg_auto_inclusion=True)


class TestCOSE:
    """
    Tests for COSE.
    """

    def test_cose_wg_examples_mac0_hmac_01(self, ctx):
        cwt_str = "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": "our-secret",
                "use": "sig",
                "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            }
        )
        encoded = ctx.encode_and_mac(
            b"This is the content.",
            key=key,
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_hmac_01(self, ctx):
        cwt_str = "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": "our-secret",
                "use": "sig",
                "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            }
        )
        encoded = ctx.encode_and_mac(
            b"This is the content.",
            key=key,
            recipients=[Recipient.new(unprotected={1: -6, 4: b"our-secret"})],
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_sign1_pass_01(self):
        # cwt_str = "D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F"
        key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            key,
            # protected=bytes.fromhex("a0"),
            unprotected={1: -7, 4: b"11"},
        )
        assert ctx.decode(encoded, key) == b"This is the content."
        # assert ctx.decode(bytes.fromhex(cwt_str), key) == b"This is the content."

    def test_cose_wg_examples_sign1_pass_02(self):
        cwt_str = "D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B"
        key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            key,
            protected={1: -7},
            unprotected={4: b"11"},
            external_aad=bytes.fromhex("11aa22bb33cc44dd55006699"),
        )
        assert ctx.decode(encoded, key, external_aad=bytes.fromhex("11aa22bb33cc44dd55006699")) == b"This is the content."
        assert (
            ctx.decode(
                bytes.fromhex(cwt_str),
                key,
                external_aad=bytes.fromhex("11aa22bb33cc44dd55006699"),
            )
            == b"This is the content."
        )

    def test_cose_wg_examples_sign_pass_01(self):
        # cwt_str = "D8628441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            signers=[signer],
            # protected=bytes.fromhex("a0"),
        )
        assert ctx.decode(encoded, signer.cose_key) == b"This is the content."
        # assert ctx.decode(bytes.fromhex(cwt_str), key) == b"This is the content."

    def test_cose_wg_examples_sign_pass_02(self):
        cwt_str = "D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840CBB8DAD9BEAFB890E1A414124D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EEB2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A"
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            signers=[signer],
            external_aad=bytes.fromhex("11aa22bb33cc44dd55006699"),
        )
        assert (
            ctx.decode(
                encoded,
                signer.cose_key,
                external_aad=bytes.fromhex("11aa22bb33cc44dd55006699"),
            )
            == b"This is the content."
        )
        assert (
            ctx.decode(
                bytes.fromhex(cwt_str),
                signer.cose_key,
                external_aad=bytes.fromhex("11aa22bb33cc44dd55006699"),
            )
            == b"This is the content."
        )

    def test_cose_wg_examples_ecdsa_01(self):
        cwt_str = "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840D71C05DB52C9CE7F1BF5AAC01334BBEACAC1D86A2303E6EEAA89266F45C01ED602CA649EAF790D8BC99D2458457CA6A872061940E7AFBE48E289DFAC146AE258"
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "11",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            signers=[signer],
            protected={3: 0},
        )
        assert ctx.decode(encoded, signer.cose_key) == b"This is the content."
        assert ctx.decode(bytes.fromhex(cwt_str), signer.cose_key) == b"This is the content."

    def test_cose_wg_examples_eddsa_01(self):
        cwt_str = "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106"
        signer = Signer.from_jwk(
            {
                "kty": "OKP",
                "kid": "11",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            signers=[signer],
            protected={3: 0},
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, signer.cose_key) == b"This is the content."

    def test_cose_wg_examples_eddsa_02(self):
        cwt_str = "D8628440A054546869732069732074686520636F6E74656E742E818343A10127A1044565643434385872ABF04F4BC7DFACF70C20C34A3CFBD27719911DC8518B2D67BF6AF62895D0FA1E6A1CB8B47AD1297C0E9C34BEB34E50DFFEF14350EBD57842807D54914111150F698543B0A5E1DA1DB79632C6415CE18EF74EDAEA680B0C8881439D869171481D78E2F7D26340C293C2ECDED8DE1425851900"
        signer = Signer.from_jwk(
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
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            signers=[signer],
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, signer.cose_key) == b"This is the content."

    def test_cose_wg_examples_eddsa_sig_01(self):
        cwt_str = "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D"
        key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "kid": "11",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
                .replace(b"=", b"")
                .decode("ascii"),
                "d": base64.urlsafe_b64encode(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
                .replace(b"=", b"")
                .decode("ascii"),
            }
        )
        ctx = COSE.new(kid_auto_inclusion=True)
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            key,
            protected={1: -8, 3: 0},
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_eddsa_sig_02(self):
        cwt_str = "D28443A10127A10445656434343854546869732069732074686520636F6E74656E742E5872988240A3A2F189BD486DE14AA77F54686C576A09F2E7ED9BAE910DF9139C2AC3BE7C27B7E10A20FA17C9D57D3510A2CF1F634BC0345AB9BE00849842171D1E9E98B2674C0E38BFCF6C557A1692B01B71015A47AC9F7748840CAD1DA80CBB5B349309FEBB912672B377C8B2072AF1598B3700"
        key = COSEKey.from_jwk(
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
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_sign(
            b"This is the content.",
            key,
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_aes_ccm_01(self, ctx):
        cwt_str = "D8608443A1010AA1054D89F52F65A1C580933B5261A72F581C6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE818340A20125044A6F75722D73656372657440"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "AES-CCM-16-64-128",
                "kid": "our-secret",
                "use": "enc",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            }
        )
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            unprotected={5: bytes.fromhex("89F52F65A1C580933B5261A72F")},
            recipients=[Recipient.new(unprotected={1: -6, 4: b"our-secret"})],
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_aes_gcm_01(self, ctx):
        # cwt_str = "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73656372657440"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128GCM",
                "kid": "our-secret",
                "use": "enc",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            }
        )
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            unprotected={5: bytes.fromhex("02D1F7E6F26C43D4870D87CE")},
            recipients=[Recipient.new(unprotected={1: -6, 4: b"our-secret"})],
        )
        # assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_chacha_poly_01(self, ctx):
        # cwt_str = "D8608444A1011818A1054C26682306D4FB28CA01B43B8058245F2BD5381BBB04921A8477E55C0D850069674A05E683D416583AA0CEE0E2929CDF648094818340A2012504477365632D32353640"
        cwt_str = "D8608444A1011818A1054C26682306D4FB28CA01B43B8058241CD5D49DAA014CCAFFB30E765DC5CD410689AAE1C60B45648853298FF6808DB3FA8235DB818340A2012504477365632D32353640"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "ChaCha20/Poly1305",
                "kid": "sec-256",
                "use": "enc",
                "k": "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA",
            }
        )
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            unprotected={5: bytes.fromhex("26682306D4FB28CA01B43B80")},
            recipients=[Recipient.new(unprotected={1: -6, 4: b"sec-256"})],
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_chacha_poly_enc_01(self, ctx):
        # cwt_str = "D08344A1011818A1054C5C3A9950BD2852F66E6C8D4F58243E536D4992A21591575C55FA22981B31AE1C045946D0E41A8A1ABD12BC9525922F4EB618"
        cwt_str = "D08344A1011818A1054C5C3A9950BD2852F66E6C8D4F5824CA119C45926DA993D29B5D0CAC9A84228C7668D492A1B9D7E32020EF21372E74DEF431B9"
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "ChaCha20/Poly1305",
                "kid": "sec-256",
                "use": "enc",
                "k": "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA",
            }
        )
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key,
            unprotected={5: bytes.fromhex("5C3A9950BD2852F66E6C8D4F")},
        )
        assert encoded == bytes.fromhex(cwt_str)
        assert ctx.decode(encoded, key) == b"This is the content."

    def test_cose_wg_examples_rfc8152_c_3_2(self):
        cwt_str = "D8608443A1010AA1054D89F52F65A1C580933B5261A76C581C753548A19B1307084CA7B2056924ED95F2E3B17006DFE931B687B847818343A10129A2335061616262636364646565666667676868044A6F75722D73656372657440"
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
            kid="our-secret",
        )
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        recipient = Recipient.new({1: -10}, {-20: b"aabbccddeeffgghh", 4: b"our-secret"}, context=context)
        ctx = COSE.new()
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key=material,
            protected={1: 10},
            unprotected={5: bytes.fromhex("89F52F65A1C580933B5261A76C")},
            recipients=[recipient],
        )
        assert encoded == bytes.fromhex(cwt_str)
        context = {
            "alg": "AES-CCM-16-64-128",
            "apu": {
                "id": "lighting-client",
            },
            "apv": {
                "id": "lighting-server",
            },
            "supp_pub": {
                "other": "Encryption Example 02",
            },
        }
        res = ctx.decode(encoded, context=context, keys=[material])
        assert res == b"This is the content."

    def test_cose_wg_examples_rfc8152_c_3_2_with_json(self):
        cwt_str = "D8608443A1010AA1054D89F52F65A1C580933B5261A76C581C753548A19B1307084CA7B2056924ED95F2E3B17006DFE931B687B847818343A10129A2335061616262636364646565666667676868044A6F75722D73656372657440"
        context = {
            "alg": "AES-CCM-16-64-128",
            "apu": {
                "id": "lighting-client",
            },
            "apv": {
                "id": "lighting-server",
            },
            "supp_pub": {
                "other": "Encryption Example 02",
            },
        }
        recipient = Recipient.new({1: -10}, {-20: b"aabbccddeeffgghh", 4: b"our-secret"}, context=context)
        material = COSEKey.from_symmetric_key(
            base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key=material,
            protected={1: 10},
            unprotected={5: bytes.fromhex("89F52F65A1C580933B5261A76C")},
            recipients=[recipient],
        )
        assert encoded == bytes.fromhex(cwt_str)
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
            kid="our-secret",
        )
        context = {
            "alg": "AES-CCM-16-64-128",
            "apu": {
                "id": "lighting-client",
            },
            "apv": {
                "id": "lighting-server",
            },
            "supp_pub": {
                "other": "Encryption Example 02",
            },
        }
        res = ctx.decode(encoded, context=context, keys=[material])
        assert res == b"This is the content."

    def test_cose_wg_examples_aes_wrap_128_03(self):
        cwt_str = "D8618543A10107A054546869732069732074686520636F6E74656E742E58400021C21B2A7FADB677DAB64389B3FDA4AAC892D5C81B786A459E4182104A1501462FFD471422AF4D48BEEB864951D5947A55E3155E670DFC4A96017B0FD0E725818340A20122044A6F75722D7365637265745848792C46CE0BC689747133FA0DB1F5E2BC4DAAE22F906E93DFCA2DF44F0DF6C2CEF16EA8FC91D52AD662C4B49DD0D689E1086EC754347957F80F95C92C887521641B8F637D91C6E258"
        mac_key = COSEKey.from_symmetric_key(
            bytes.fromhex(
                "DDDC08972DF9BE62855291A17A1B4CF767C2DC762CB551911893BF7754988B0A286127BFF5D60C4CBC877CAC4BF3BA02C07AD544C951C3CA2FC46B70219BC3DC"
            ),
            alg="HS512",
        )
        key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "our-secret",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        recipient = Recipient.new(
            unprotected={
                "alg": "A128KW",
                "kid": "our-secret",
            },
            sender_key=key,
        )
        ctx = COSE.new()
        encoded = ctx.encode_and_mac(
            b"This is the content.",
            key=mac_key,
            protected={1: 7},
            recipients=[recipient],
        )
        assert encoded == bytes.fromhex(cwt_str)
        res = ctx.decode(encoded, keys=[key])
        assert res == b"This is the content."

    def test_cose_wg_examples_ecdh_direct_p256_hkdf_256_01(self):
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "meriadoc.brandybuck@buckland.example",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        rec = Recipient.new(
            unprotected={
                "alg": "ECDH-ES+HKDF-256",
            },
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            recipients=[rec],
        )
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "meriadoc.brandybuck@buckland.example",
                "crv": "P-256",
                "alg": "ECDH-ES+HKDF-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"This is the content." == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_wg_examples_ecdh_wrap_p256_ss_wrap_128_01(self):
        # The sender side:
        enc_key = COSEKey.from_symmetric_key(
            # bytes.fromhex("B2353161740AACF1F7163647984B522A"),
            alg="A128GCM",
        )
        sender_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
                "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
                "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
            }
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                # "d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
            }
        )
        rec = Recipient.new(
            unprotected={
                "alg": "ECDH-SS+A128KW",
            },
            sender_key=sender_priv_key,
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"This is the content.",
            key=enc_key,
            unprotected={5: b"\x02\xd1\xf7\xe6\xf2lC\xd4\x86\x8d\x87\xce"},
            recipients=[rec],
        )

        # The recipient side:
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"This is the content." == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})
