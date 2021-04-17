# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for samples on README and RFCs related to CWT/COSE.
"""
# import cbor2
# import pytest
from secrets import token_bytes

import cwt
from cwt import claims, cose_key

from .utils import key_path

# A sample of 128-Bit Symmetric Key referred from RFC8392
SAMPLE_COSE_KEY_RFC8392_A2_1 = (
    "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a"
)

# A sample of 256-Bit Symmetric Key referred from RFC8392
SAMPLE_COSE_KEY_RFC8392_A2_2 = (
    "a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d"
    "795693880104024c53796d6d6574726963323536030a"
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

    def test_sample_readme_maced_cwt_with_json_dict(self):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        encoded = cwt.encode_and_mac(
            claims.from_json(
                {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}
            ),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_maced_cwt_with_json_str(self):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        encoded = cwt.encode_and_mac(
            claims.from_json(
                '{"iss":"https://as.example","sub":"dajiaji","cti":"123"}'
            ),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_maced_cwt_with_json_bytes(self):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        encoded = cwt.encode_and_mac(
            claims.from_json(
                b'{"iss":"https://as.example","sub":"dajiaji","cti":"123"}'
            ),
            key,
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_maced_cwt(self):
        """"""
        key = cose_key.from_symmetric_key("mysecretpassword")
        encoded = cwt.encode_and_mac(
            {1: "https://as.example", 2: "dajiaji", 7: b"123"}, key
        )
        decoded = cwt.decode(encoded, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_signed_cwt_es256(self):
        """"""
        # Load PEM-formatted keys as COSE keys.
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read())
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read())

        # Encode with ES256 signing.
        encoded = cwt.encode_and_sign(
            claims.from_json(
                {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}
            ),
            private_key,
        )

        # Verify and decode.
        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_signed_cwt_ed25519(self):
        """"""
        # Load PEM-formatted keys as COSE keys.
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read())
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read())

        # Encode with Ed25519 encryption.
        encoded = cwt.encode_and_sign(
            claims.from_json(
                {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}
            ),
            private_key,
        )

        # Verify and decode.
        decoded = cwt.decode(encoded, public_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_encrypted_cwt(self):
        """"""
        nonce = token_bytes(13)
        mysecret = token_bytes(32)
        enc_key = cose_key.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256")
        encoded = cwt.encode_and_encrypt(
            claims.from_json(
                {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}
            ),
            enc_key,
            nonce=nonce,
        )
        decoded = cwt.decode(encoded, enc_key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_readme_nested_cwt(self):
        """"""
        # Load PEM-formatted keys as COSE keys.
        with open(key_path("private_key_es256.pem")) as key_file:
            private_key = cose_key.from_pem(key_file.read())
        with open(key_path("public_key_es256.pem")) as key_file:
            public_key = cose_key.from_pem(key_file.read())

        # Encode with ES256 signing.
        encoded = cwt.encode_and_sign(
            claims.from_json(
                {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}
            ),
            private_key,
        )

        # Encrypt the signed CWT.
        nonce = token_bytes(13)
        mysecret = token_bytes(32)
        enc_key = cose_key.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256")
        nested = cwt.encode_and_encrypt(encoded, enc_key, nonce=nonce)

        # Decrypt and verify the nested CWT.
        decoded = cwt.decode(nested, [enc_key, public_key])
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "dajiaji"
        assert 7 in decoded and decoded[7] == b"123"

    def test_sample_rfc8392_a3(self):
        """"""
        key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        encoded = bytes.fromhex(SAMPLE_CWT_RFC8392_A3)
        decoded = cwt.decode(encoded, key=key)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a3_with_encoding(self):
        """"""
        key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
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
        decoded = cwt.decode(encoded, key=key)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a4(self):
        """"""
        key = cose_key.from_dict(
            {
                -1: bytes.fromhex(
                    "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"
                ),
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
        decoded = cwt.decode(encoded, key=key)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a5(self):
        """"""
        key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
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
        decoded = cwt.decode(encoded, key=key)
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a6(self):
        """"""
        sig_key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
        enc_key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        encrypted = bytes.fromhex(SAMPLE_CWT_RFC8392_A6)
        decoded = cwt.decode(encrypted, key=[enc_key, sig_key])
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")

    def test_sample_rfc8392_a6_with_encoding(self):
        """"""
        sig_key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_3))
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
        enc_key = cose_key.from_bytes(bytes.fromhex(SAMPLE_COSE_KEY_RFC8392_A2_1))
        nonce = bytes.fromhex("4a0694c0e69ee6b5956655c7b2")
        encrypted = cwt.encode_and_encrypt(signed, key=enc_key, nonce=nonce)
        decoded = cwt.decode(encrypted, key=[enc_key, sig_key])
        assert 1 in decoded and decoded[1] == "coap://as.example.com"
        assert 2 in decoded and decoded[2] == "erikw"
        assert 3 in decoded and decoded[3] == "coap://light.example.com"
        assert 4 in decoded and decoded[4] == 1444064944
        assert 5 in decoded and decoded[5] == 1443944944
        assert 6 in decoded and decoded[6] == 1443944944
        assert 7 in decoded and decoded[7] == bytes.fromhex("0b71")
