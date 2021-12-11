# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for samples on README and RFCs related to CWT/COSE.
"""
from secrets import token_bytes

import pytest

import cwt
from cwt import CWT, Claims, COSEKey, EncryptedCOSEKey, VerifyError, load_pem_hcert_dsc

from .utils import key_path, now

# A sample of 128-Bit Symmetric Key referred from RFC8392
SAMPLE_COSE_KEY_RFC8392_A2_1 = "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a"

# A sample of 256-Bit Symmetric Key referred from RFC8392
SAMPLE_COSE_KEY_RFC8392_A2_2 = (
    "a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d" "795693880104024c53796d6d6574726963323536030a"
)

# A sample of ECDSA P-256 256-Bit COSE Key referred from RFC8392
SAMPLE_COSE_KEY_RFC8392_A2_3 = (
    "a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858"
    "bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db"
    "9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7e"
    "ca69ed8919a394d42f0f2001010202524173796d6d6574726963454344534132"
    "35360326"
)

# A sample of Signed CWT referred from RFC8392
SAMPLE_CWT_RFC8392_A3 = (
    "d28443a10126a104524173796d6d657472696345434453413235365850a70175"
    "636f61703a2f2f61732e6578616d706c652e636f6d02656572696b7703781863"
    "6f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a56"
    "10d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e60"
    "1d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee"
    "743a52b9b63632c57209120e1c9e30"
)

# A sample of MACed CWT referred from RFC8392
SAMPLE_CWT_RFC8392_A4 = (
    "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f6170"
    "3a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a"
    "2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006"
    "1a5610d9f007420b7148093101ef6d789200"
)

# A sample of Encrypted CWT referred from RFC8392
SAMPLE_CWT_RFC8392_A5 = (
    "d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ff"
    "e8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562"
    "f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d"
    "45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b"
)

# A Sample of Nested CWT referred from RFC8392
SAMPLE_CWT_RFC8392_A6 = (
    "d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b595"
    "6655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e"
    "7de05650dec74724366763f167a29c002dfd15b34d8993391cf49bc91127f545"
    "dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49"
    "af768b23179deab78d96490a66d5724fb33900c60799d9872fac6da3bdb89043"
    "d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631"
    "610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0"
)


class TestSample:
    """
    Tests for samples in README or in RFCs related to CWT/COSE.
    """

    def test_sample_readme_maced_cwt_with_json_dict_old(self):
        key = COSEKey.from_symmetric_key("mysecretpassword", alg="HS256", kid="01")
        encoded = cwt.encode_and_mac(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 4 in decoded and decoded[4] <= now() + 3600
        assert 5 in decoded and decoded[5] <= now()
        assert 6 in decoded and decoded[6] <= now()
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_maced_cwt_with_json_dict(self):
        key = COSEKey.from_symmetric_key(alg="HMAC 256/256", kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
        decoded = cwt.decode(token, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt_with_json_str_old(self):
        key = COSEKey.from_symmetric_key("mysecretpassword", alg="HS256", kid="01")
        encoded = cwt.encode_and_mac(
            Claims.from_json('{"iss":"coaps://as.example","sub":"dajiaji","cti":"123"}'),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt_with_json_str(self):
        key = COSEKey.from_symmetric_key(alg="HMAC 256/256", kid="01")
        token = cwt.encode('{"iss":"coaps://as.example","sub":"dajiaji","cti":"123"}', key)
        decoded = cwt.decode(token, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt_with_json_bytes_old(self):
        key = COSEKey.from_symmetric_key("mysecretpassword", alg="HS256", kid="01")
        encoded = cwt.encode_and_mac(
            Claims.from_json(b'{"iss":"coaps://as.example","sub":"dajiaji","cti":"123"}'),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt_with_json_bytes(self):
        key = COSEKey.from_symmetric_key(alg="HMAC 256/256", kid="01")
        token = cwt.encode(b'{"iss":"coaps://as.example","sub":"dajiaji","cti":"123"}', key)
        decoded = cwt.decode(token, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt_old(self):
        key = COSEKey.from_symmetric_key("mysecretpassword", alg="HS256", kid="01")
        encoded = cwt.encode_and_mac({1: "coaps://as.example", 2: "dajiaji", 7: b"123"}, key)
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_maced_cwt(self):
        key = COSEKey.from_symmetric_key(alg="HMAC 256/256", kid="01")
        token = cwt.encode({1: "coaps://as.example", 2: "dajiaji", 7: b"123"}, key)
        decoded = cwt.decode(token, key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256_old(self):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        encoded = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )

        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256(self):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256_with_cert(self):
        # with open(key_path("cacert.pem")) as f:
        #     k1 = x509.load_pem_x509_certificate(f.read().encode("utf-8"))

        # with open(key_path("cert_es256.pem")) as f:
        #     k2 = x509.load_pem_x509_certificate(f.read().encode("utf-8"))

        # x5c = [
        #     base64url_encode(k1.public_bytes(serialization.Encoding.DER)).decode("utf-8"),
        #     base64url_encode(k2.public_bytes(serialization.Encoding.DER)).decode("utf-8"),
        # ]

        with open(key_path("private_key_cert_es256.pem")) as f:
            private_key = COSEKey.from_pem(f.read(), kid="P-256-01")

        with open(key_path("cert_es256.json")) as f:
            public_key = COSEKey.from_jwk(f.read())

        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        decoder = CWT.new(ca_certs=key_path("cacert.pem"))
        decoded = decoder.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256_with_cert_without_intermediates(self):
        with open(key_path("private_key_cert_es256.pem")) as f:
            private_key = COSEKey.from_pem(f.read(), kid="P-256-01")

        with open(key_path("cert_es256_2.json")) as f:
            public_key = COSEKey.from_jwk(f.read())

        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        decoder = CWT.new(ca_certs=key_path("cacert.pem"))
        decoded = decoder.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256_with_another_ca_cert(self):
        with open(key_path("private_key_cert_es256.pem")) as f:
            private_key = COSEKey.from_pem(f.read(), kid="P-256-01")

        with open(key_path("cert_es256.json")) as f:
            public_key = COSEKey.from_jwk(f.read())

        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        decoder = CWT.new(ca_certs=key_path("cacert_2.pem"))
        with pytest.raises(VerifyError) as err:
            decoder.decode(token, public_key)
            pytest.fail("decode() should fail.")
        assert "Failed to validate the certificate bound to the key." in str(err.value)

    def test_sample_readme_signed_cwt_es384_old(self):
        with open(key_path("private_key_es384.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_es384.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")

        encoded = cwt.encode_and_sign(
            Claims.from_json(
                {
                    "iss": "coaps://as.example",
                    "sub": "dajiaji",
                    "aud": ["coaps://rs1.example", "coaps://rs2.example"],
                    "cti": "123",
                }
            ),
            private_key,
        )

        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"
        assert 3 in decoded and isinstance(decoded[3], list)
        assert 3 in decoded and decoded[3][0] == "coaps://rs1.example"
        assert 3 in decoded and decoded[3][1] == "coaps://rs2.example"

    def test_sample_readme_signed_cwt_es384(self):
        with open(key_path("private_key_es384.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_es384.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es512_old(self):
        with open(key_path("private_key_es512.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )

        with open(key_path("public_key_es512.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es512(self):
        with open(key_path("private_key_es512.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_es512.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256k_old(self):
        with open(key_path("private_key_es256k.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )

        with open(key_path("public_key_es256k.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_es256k(self):
        with open(key_path("private_key_es256k.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_es256k.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_ed25519_old(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_ed25519(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_ed25519_with_jwk(self):

        # The sender side:
        private_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "key_ops": ["sign"],
                "alg": "EdDSA",
                "crv": "Ed25519",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            }
        )
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        # The recipient side:
        public_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "key_ops": ["verify"],
                "crv": "Ed25519",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            }
        )
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_rs256(self):
        with open(key_path("private_key_rsa.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="RS256", kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_rsa.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), alg="RS256", kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_signed_cwt_ps256(self):
        with open(key_path("private_key_rsa.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), alg="PS256", kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

        with open(key_path("public_key_rsa.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), alg="PS256", kid="01")
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_encrypted_cwt_old(self):
        nonce = token_bytes(13)
        mysecret = token_bytes(32)
        enc_key = COSEKey.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256", kid="01")
        encoded = cwt.encode_and_encrypt(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            enc_key,
            nonce=nonce,
        )
        decoded = cwt.decode(encoded, enc_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_encrypted_cwt(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key)
        decoded = cwt.decode(token, enc_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_nested_cwt_old(self):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )
        nonce = token_bytes(13)
        mysecret = token_bytes(32)
        enc_key = COSEKey.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256", kid="02")
        nested = cwt.encode_and_encrypt(encoded, enc_key, nonce=nonce)

        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(nested, [enc_key, public_key])
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_nested_cwt(self):
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="02")
        nested = cwt.encode(token, enc_key)

        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(nested, [enc_key, public_key])
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_nested_cwt_without_kid(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")

        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read())
        ctx = CWT.new()
        ctx.cose.verify_kid = False
        token = ctx.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key)
        nested = ctx.encode(token, enc_key)

        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read())

        decoded = ctx.decode(nested, [enc_key, public_key])
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_readme_cwt_with_pop_jwk(self):

        # issuer:
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        token = cwt.encode(
            {
                "iss": "coaps://as.example",
                "sub": "dajiaji",
                "cti": "123",
                "cnf": {
                    "jwk": {
                        "kty": "OKP",
                        "use": "sig",
                        "crv": "Ed25519",
                        "kid": "01",
                        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                        "alg": "EdDSA",
                    },
                },
            },
            private_key,
        )

        # presenter:
        msg = b"could-you-sign-this-message?"  # Provided by recipient.
        pop_key_private = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
                "use": "sig",
                "crv": "Ed25519",
                "kid": "01",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "alg": "EdDSA",
            }
        )
        sig = pop_key_private.sign(msg)

        # recipient:
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 1 in decoded[8] and isinstance(decoded[8][1], dict)
        c = Claims.new(decoded)
        extracted = COSEKey.new(c.cnf)
        try:
            extracted.verify(msg, sig)
        except Exception:
            pytest.fail("verify should not fail.")

    def test_sample_readme_cwt_with_pop_encrypted_cose_key_readable(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        enc_key = COSEKey.from_symmetric_key(
            "a-client-secret-of-cwt-recipient",  # Just 32 bytes!
            alg="ChaCha20/Poly1305",
            kid="presenter-01",
        )
        pop_key = COSEKey.from_symmetric_key(
            "a-client-secret-of-cwt-presenter",
            alg="HMAC 256/256",
        )
        token = cwt.encode(
            {
                "iss": "coaps://as.example",
                "sub": "dajiaji",
                "cti": "123",
                "cnf": {
                    # 'eck'(Encrypted Cose Key) is a keyword defined by this library.
                    "eck": EncryptedCOSEKey.from_cose_key(pop_key, enc_key),
                },
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 2 in decoded[8] and isinstance(decoded[8][2], list)
        c = Claims.new(decoded)
        extracted = EncryptedCOSEKey.to_cose_key(c.cnf, enc_key)
        assert extracted.kty == 4  # Symmetric
        assert extracted.alg == 5  # HMAC 256/256
        assert extracted.key == b"a-client-secret-of-cwt-presenter"

    def test_sample_readme_cwt_with_pop_kid_readable(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

        token = cwt.encode(
            {
                "iss": "coaps://as.example",
                "sub": "dajiaji",
                "cti": "123",
                "cnf": {
                    "kid": "pop-key-id-of-cwt-presenter",
                },
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 3 in decoded[8] and decoded[8][3] == b"pop-key-id-of-cwt-presenter"
        c = Claims.new(decoded)
        assert c.cnf == "pop-key-id-of-cwt-presenter"

    def test_sample_readme_cwt_with_pop_cose_key(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        with open(key_path("public_key_es256.pem")) as key_file:
            pop_key = COSEKey.from_pem(key_file.read())
        token = cwt.encode(
            {
                1: "coaps://as.example",  # iss
                2: "dajiaji",  # sub
                7: b"123",  # cti
                8: {  # cnf
                    1: pop_key.to_dict(),
                },
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 1 in decoded[8] and isinstance(decoded[8][1], dict)
        extracted = COSEKey.new(decoded[8][1])
        assert extracted.kty == 2  # EC2
        assert extracted.crv == 1  # P-256

    def test_sample_readme_cwt_with_pop_encrypted_cose_key(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        enc_key = COSEKey.from_symmetric_key(
            "a-client-secret-of-cwt-recipient",  # Just 32 bytes!
            alg="ChaCha20/Poly1305",
            kid="presenter-01",
        )
        pop_key = COSEKey.from_symmetric_key(
            "a-client-secret-of-cwt-presenter",
            alg="HMAC 256/256",
        )
        token = cwt.encode(
            {
                1: "coaps://as.example",  # iss
                2: "dajiaji",  # sub
                7: b"123",  # cti
                8: {  # cnf
                    2: EncryptedCOSEKey.from_cose_key(pop_key, enc_key),
                },
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 2 in decoded[8] and isinstance(decoded[8][2], list)
        extracted = EncryptedCOSEKey.to_cose_key(decoded[8][2], enc_key)
        assert extracted.kty == 4  # Symmetric
        assert extracted.alg == 5  # HMAC 256/256
        assert extracted.key == b"a-client-secret-of-cwt-presenter"

    def test_sample_readme_cwt_with_pop_kid(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode(
            {
                1: "coaps://as.example",  # iss
                2: "dajiaji",  # sub
                7: b"123",  # cti
                8: {  # cnf
                    3: b"pop-key-id-of-cwt-presenter",
                },
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        decoded = cwt.decode(token, public_key)
        assert 8 in decoded and isinstance(decoded[8], dict)
        assert 3 in decoded[8] and decoded[8][3] == b"pop-key-id-of-cwt-presenter"

    def test_sample_readme_cwt_with_user_defined_claims(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        token = cwt.encode(
            {
                1: "coaps://as.example",  # iss
                2: "dajiaji",  # sub
                7: b"123",  # cti
                -70001: "foo",
                -70002: ["bar"],
                -70003: {"baz": "qux"},
                -70004: 123,
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        raw = cwt.decode(token, public_key)
        assert raw[-70001] == "foo"
        assert isinstance(raw[-70002], list)
        assert raw[-70002][0] == "bar"
        assert isinstance(raw[-70003], dict)
        assert raw[-70003]["baz"] == "qux"
        assert raw[-70004] == 123
        readable = Claims.new(raw)
        assert readable.get(-70001) == "foo"
        assert readable.get(-70002)[0] == "bar"
        assert readable.get(-70003)["baz"] == "qux"
        assert readable.get(-70004) == 123

    def test_sample_readme_cwt_with_user_defined_claims_readable(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="01")
        cwt.set_private_claim_names(
            {
                "ext_1": -70001,
                "ext_2": -70002,
                "ext_3": -70003,
                "ext_4": -70004,
            }
        )
        token = cwt.encode(
            {
                "iss": "coaps://as.example",
                "sub": "dajiaji",
                "cti": b"123",
                "ext_1": "foo",
                "ext_2": ["bar"],
                "ext_3": {"baz": "qux"},
                "ext_4": 123,
            },
            private_key,
        )

        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid="01")
        raw = cwt.decode(token, public_key)
        readable = Claims.new(
            raw,
            private_claim_names={
                "ext_1": -70001,
                "ext_2": -70002,
                "ext_3": -70003,
                "ext_4": -70004,
            },
        )
        assert readable.get("ext_1") == "foo"
        assert readable.get("ext_2")[0] == "bar"
        assert readable.get("ext_3")["baz"] == "qux"
        assert readable.get("ext_4") == 123

    def test_sample_readme_decode_with_multiple_keys(self):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid="02")
        token = cwt.encode(
            {
                "iss": "coaps://as.example",
                "sub": "dajiaji",
                "cti": b"123",
            },
            private_key,
        )

        with open(key_path("public_key_es256.pem")) as key_file:
            public_key_1 = COSEKey.from_pem(key_file.read(), kid="01")
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key_2 = COSEKey.from_pem(key_file.read(), kid="02")
        decoded = cwt.decode(token, [public_key_1, public_key_2])
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    def test_sample_rfc8392_a3(self):
        key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        encoded = bytes.fromhex(SAMPLE_CWT_RFC8392_A3)
        decoded = cwt.decode(encoded, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a3_with_encoding_old(self):
        key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        encoded = cwt.encode_and_sign(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=key,
        )
        decoded = cwt.decode(encoded, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a3_with_encoding(self):
        key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        token = cwt.encode(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key,
        )
        decoded = cwt.decode(token, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a4_old(self):
        key = COSEKey.new(
            {
                -1: bytes.fromhex("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
                1: 4,  # Symmetric
                2: bytes.fromhex("53796d6d6574726963323536"),
                3: 4,  # HMAC256/64
            }
        )
        encoded = cwt.encode_and_mac(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=key,
            tagged=True,
        )
        assert encoded == bytes.fromhex(SAMPLE_CWT_RFC8392_A4)
        decoded = cwt.decode(encoded, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a4(self):
        key = COSEKey.new(
            {
                -1: bytes.fromhex("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
                1: 4,  # Symmetric
                2: bytes.fromhex("53796d6d6574726963323536"),
                3: 4,  # HMAC256/64
            }
        )
        token = cwt.encode(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key,
            tagged=True,
        )
        assert token == bytes.fromhex(SAMPLE_CWT_RFC8392_A4)
        decoded = cwt.decode(token, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a5_old(self):
        key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        nonce = bytes.fromhex("99a0d7846e762c49ffe8a63e0b")
        encoded = cwt.encode_and_encrypt(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=key,
            nonce=nonce,
        )
        assert encoded == bytes.fromhex(SAMPLE_CWT_RFC8392_A5)
        decoded = cwt.decode(encoded, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a5(self):
        key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        nonce = bytes.fromhex("99a0d7846e762c49ffe8a63e0b")
        token = cwt.encode(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=key,
            nonce=nonce,
        )
        assert token == bytes.fromhex(SAMPLE_CWT_RFC8392_A5)
        decoded = cwt.decode(token, keys=key, no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a6(self):
        sig_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        enc_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        encrypted = bytes.fromhex(SAMPLE_CWT_RFC8392_A6)
        decoded = cwt.decode(encrypted, keys=[enc_key, sig_key], no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a6_with_encoding_old(self):
        sig_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        signed = cwt.encode_and_sign(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=sig_key,
        )
        enc_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        nonce = bytes.fromhex("4a0694c0e69ee6b5956655c7b2")
        encrypted = cwt.encode_and_encrypt(signed, key=enc_key, nonce=nonce)
        decoded = cwt.decode(encrypted, keys=[enc_key, sig_key], no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_rfc8392_a6_with_encoding(self):
        sig_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        signed = cwt.encode(
            {
                1: "coap://as.example.com",
                2: "erikw",
                3: "coap://light.example.com",
                4: 1444064944,
                5: 1443944944,
                6: 1443944944,
                7: bytes.fromhex("0b71"),
            },
            key=sig_key,
        )
        enc_key = COSEKey.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        nonce = bytes.fromhex("4a0694c0e69ee6b5956655c7b2")
        encrypted = cwt.encode(signed, key=enc_key, nonce=nonce)
        decoded = cwt.decode(encrypted, keys=[enc_key, sig_key], no_verify=True)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"

    def test_sample_hcert_testdata_AT_2DCode_raw_1(self):

        # A DSC(Document Signing Certificate) issued by a CSCA (Certificate Signing Certificate Authority).
        dsc = "-----BEGIN CERTIFICATE-----\nMIIBvTCCAWOgAwIBAgIKAXk8i88OleLsuTAKBggqhkjOPQQDAjA2MRYwFAYDVQQDDA1BVCBER0MgQ1NDQSAxMQswCQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMB4XDTIxMDUwNTEyNDEwNloXDTIzMDUwNTEyNDEwNlowPTERMA8GA1UEAwwIQVQgRFNDIDExCzAJBgNVBAYTAkFUMQ8wDQYDVQQKDAZCTVNHUEsxCjAIBgNVBAUTATEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASt1Vz1rRuW1HqObUE9MDe7RzIk1gq4XW5GTyHuHTj5cFEn2Rge37+hINfCZZcozpwQKdyaporPUP1TE7UWl0F3o1IwUDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFO49y1ISb6cvXshLcp8UUp9VoGLQMB8GA1UdIwQYMBaAFP7JKEOflGEvef2iMdtopsetwGGeMAoGCCqGSM49BAMCA0gAMEUCIQDG2opotWG8tJXN84ZZqT6wUBz9KF8D+z9NukYvnUEQ3QIgdBLFSTSiDt0UJaDF6St2bkUQuVHW6fQbONd731/M4nc=\n-----END CERTIFICATE-----"

        # An EUDCC (EU Digital COVID Certificate)
        eudcc = bytes.fromhex(
            "d2844da20448d919375fc1e7b6b20126a0590133a4041a61817ca0061a60942ea001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d323658405812fce67cb84c3911d78e3f61f890d0c80eb9675806aebed66aa2d0d0c91d1fc98d7bcb80bf00e181806a9502e11b071325901bd0d2c1b6438747b8cc50f521"
        )

        public_key = load_pem_hcert_dsc(dsc)
        decoded = cwt.decode(eudcc, keys=[public_key], no_verify=True)
        claims = Claims.new(decoded)

        assert 1 in claims.hcert
        assert isinstance(claims.hcert[1], dict)
        assert "v" in claims.hcert[1]
        assert "nam" in claims.hcert[1]
        assert "dob" in claims.hcert[1]
        assert "ver" in claims.hcert[1]
        assert isinstance(claims.hcert[1]["v"], list)
        assert len(claims.hcert[1]["v"]) == 1
        assert isinstance(claims.hcert[1]["v"][0], dict)
        assert isinstance(claims.hcert[1]["nam"], dict)
        assert "fnt" in claims.hcert[1]["nam"]
        assert claims.hcert[1]["nam"]["fnt"] == "MUSTERFRAU<GOESSINGER"
        assert claims.hcert[1]["dob"] == "1998-02-26"
        assert claims.hcert[1]["ver"] == "1.0.0"

    def test_sample_hcert_testdata_AT_2DCode_raw_1_with_cert_file(self):
        eudcc = bytes.fromhex(
            "d2844da20448d919375fc1e7b6b20126a0590133a4041a61817ca0061a60942ea001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d323658405812fce67cb84c3911d78e3f61f890d0c80eb9675806aebed66aa2d0d0c91d1fc98d7bcb80bf00e181806a9502e11b071325901bd0d2c1b6438747b8cc50f521"
        )

        with open(key_path("hcert_testdata_cert_at.pem")) as key_file:
            dsc = key_file.read()
            public_key = load_pem_hcert_dsc(dsc)
        decoded = cwt.decode(eudcc, keys=[public_key], no_verify=True)
        claims = Claims.new(decoded)

        assert 1 in claims.hcert
        assert isinstance(claims.hcert[1], dict)
        assert "v" in claims.hcert[1]
        assert "nam" in claims.hcert[1]
        assert "dob" in claims.hcert[1]
        assert "ver" in claims.hcert[1]
        assert isinstance(claims.hcert[1]["v"], list)
        assert len(claims.hcert[1]["v"]) == 1
        assert isinstance(claims.hcert[1]["v"][0], dict)
        assert isinstance(claims.hcert[1]["nam"], dict)
        assert "fnt" in claims.hcert[1]["nam"]
        assert claims.hcert[1]["nam"]["fnt"] == "MUSTERFRAU<GOESSINGER"
        assert claims.hcert[1]["dob"] == "1998-02-26"
        assert claims.hcert[1]["ver"] == "1.0.0"
