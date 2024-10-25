"""
Tests for Core Deterministic Encoding.
"""

import cbor2
import pytest

from cwt import COSE, COSEKey
from cwt.const import COSE_ALGORITHMS_MAC, COSE_ALGORITHMS_SIGNATURE
from cwt.utils import sort_keys_for_deterministic_encoding


class TestDeterministicEncoding:
    """
    Tests for Core Deterministic Encoding
    """

    def test_deterministically_sorted_dict(self):
        expected = {}
        expected[0] = 0  # Reserved
        expected[1] = 0  # alg
        expected[4] = 0  # kid
        expected[5] = 0  # IV
        expected[7] = 0  # counter signature
        expected[11] = 0  # Countersignature version 2
        expected[12] = 0  # Countersignature0 version 2
        expected[15] = 0  # CWT Claims
        expected[33] = 0  # x5chain
        expected[-1] = 0  # (max of COSE Header Algorithm Parameters resistry)
        expected[-65536] = 0  # (min of COSE Header Algorithm Parameters resistry)
        expected[-65537] = 0  # (max of Reserved for Private Use)

        d = {}
        d[4] = 0
        d[-1] = 0
        d[33] = 0
        d[7] = 0
        d[11] = 0
        d[1] = 0
        d[5] = 0
        d[-65537] = 0
        d[0] = 0
        d[15] = 0
        d[12] = 0
        d[-65536] = 0

        assert expected == sort_keys_for_deterministic_encoding(d)

    def test_deterministic_cose_sign_binary(self):
        sign_jwk = {
            "kty": "EC",
            "kid": "11",
            "alg": "ES256",
            "crv": "P-256",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
        }
        sign_key = COSEKey.from_jwk(sign_jwk)

        # create unsorted protected header
        p = {}
        p["kid"] = sign_jwk["kid"]  # 4
        p["alg"] = sign_jwk["alg"]  # 1

        ctx = COSE.new(deterministic_header=True)
        encoded = ctx.encode_and_sign(
            payload=b"a",
            key=sign_key,
            protected=p,
        )
        encoded_p = cbor2.loads(encoded).value[0]

        sorted_p = {}
        sorted_p[1] = COSE_ALGORITHMS_SIGNATURE[sign_jwk["alg"]]  # -7 for ES256
        sorted_p[4] = str.encode(sign_jwk["kid"])  # b'11'
        expected_p = cbor2.dumps(sorted_p)

        assert expected_p == encoded_p

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
        ],
    )
    def test_deterministic_cose_mac_binary(self, alg):
        mac_key = COSEKey.generate_symmetric_key(alg=alg)

        # create unsorted protected header
        p = {}
        p["kid"] = "01"  # 4
        p["alg"] = alg  # 1

        ctx = COSE.new(deterministic_header=True)
        encoded = ctx.encode_and_mac(
            payload=b"a",
            key=mac_key,
            protected=p,
        )
        encoded_p = cbor2.loads(encoded).value[0]

        sorted_p = {}
        sorted_p[1] = COSE_ALGORITHMS_MAC[alg]
        sorted_p[4] = str.encode("01")
        expected_p = cbor2.dumps(sorted_p)

        assert expected_p == encoded_p
