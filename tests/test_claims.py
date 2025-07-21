# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Claims.
"""
import pytest

from cwt import Claims
from cwt.enums import CWTClaims


class TestClaims:
    """
    Tests for Claims.
    """

    def test_claims_constructor(self):
        c = Claims({})
        assert isinstance(c, Claims)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {CWTClaims.CNF: "xxx"},
                "cnf(8) should be dict.",
            ),
            (
                {CWTClaims.CNF: {0: {}}},
                "cnf(8) should include COSE_Key, Encrypted_COSE_Key, or kid.",
            ),
            (
                {CWTClaims.CNF: {1: "xxx"}},
                "COSE_Key in cnf(8) should be dict.",
            ),
            (
                {CWTClaims.CNF: {2: "xxx"}},
                "Encrypted_COSE_Key in cnf(8) should be list.",
            ),
            (
                {CWTClaims.CNF: {3: "xxx"}},
                "kid in cnf(8) should be bytes.",
            ),
        ],
    )
    def test_claims_constructor_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            Claims(invalid)
            pytest.fail("Claims should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "json, expected",
        [
            ({"iss": "coap://as.example.com"}, {CWTClaims.ISS: "coap://as.example.com"}),
            ({"sub": "erikw"}, {CWTClaims.SUB: "erikw"}),
            ({"aud": "coap://light.example.com"}, {CWTClaims.AUD: "coap://light.example.com"}),
            ({"exp": 1444064944}, {CWTClaims.EXP: 1444064944}),
            ({"nbf": 1443944944}, {CWTClaims.NBF: 1443944944}),
            ({"iat": 1443944944}, {CWTClaims.IAT: 1443944944}),
            ({"cti": "123"}, {CWTClaims.CTI: b"123"}),
            ({}, {}),
        ],
    )
    def test_claims_from_json(self, json, expected):
        claims = Claims.from_json(json).to_dict()
        for k, v in claims.items():
            assert v == expected[k]
            assert isinstance(v, type(expected[k]))
        assert len(claims) == len(expected)

    @pytest.mark.parametrize(
        "json",
        [
            {
                "iss": "coap://as.example.com",
                "sub": "erikw",
                "aud": "coap://light.example.com",
                "cti": "123",
                "exp": 1444064944,
                "nbf": 1443944944,
                "iat": 1443944944,
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
        ],
    )
    def test_claims_from_json_with_cnf(self, json):
        claims = Claims.from_json(json)
        assert claims.iss == "coap://as.example.com"
        assert claims.sub == "erikw"
        assert claims.aud == "coap://light.example.com"
        assert claims.cti == "123"
        assert claims.exp == 1444064944
        assert claims.nbf == 1443944944
        assert claims.iat == 1443944944
        assert isinstance(claims.cnf, dict)

    def test_claims_from_json_with_empty_object(self):
        claims = Claims.from_json({})
        assert claims.iss is None
        assert claims.sub is None
        assert claims.aud is None
        assert claims.cti is None
        assert claims.exp is None
        assert claims.nbf is None
        assert claims.iat is None
        assert claims.cnf is None

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {CWTClaims.ISS: "coap://as.example.com"},
                "It is already CBOR-like format.",
            ),
            (
                {"cnf": "xxx"},
                "cnf value should be dict.",
            ),
            (
                {"cnf": {"foo": "bar"}},
                "Supported cnf value not found.",
            ),
        ],
    )
    def test_claims_from_json_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            Claims.from_json(invalid)
            pytest.fail("from_json should fail.")
        assert msg in str(err.value)

    def test_claims_from_json_with_undefined_key(self):
        claims = Claims.from_json(
            {
                "iss": "coap://as.example.com",
                "ext1": "foo",
            },
            {"ext": -70001},
        )
        assert claims.get("ext1") is None

    def test_claims_from_json_with_unknown_key(self):
        claims = Claims.from_json(
            {
                "iss": "coap://as.example.com",
                "unknown": "something",
            }
        ).to_dict()
        assert len(claims) == 1
        assert claims[CWTClaims.ISS] == "coap://as.example.com"

    def test_claims_from_json_with_private_claim_names(self):
        claims = Claims.from_json(
            {
                "iss": "coap://as.example.com",
                "ext": "foo",
            },
            private_claim_names={"ext": -70001},
        ).to_dict()
        assert len(claims) == 2
        assert claims[CWTClaims.ISS] == "coap://as.example.com"
        assert claims[-70001] == "foo"

    def test_claims_from_json_with_well_known_value(self):
        with pytest.raises(ValueError) as err:
            Claims.from_json(
                {
                    "iss": "coap://as.example.com",
                    "ext1": "foo",
                },
                private_claim_names={"ext": CWTClaims.ISS},
            )
            pytest.fail("from_json should fail.")
        assert (
            "The claim key should be other than the values listed in https://python-cwt.readthedocs.io/en/stable/claims.html."
            in str(err.value)
        )
