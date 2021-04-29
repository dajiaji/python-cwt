# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for ClaimsBuilder.
"""
import pytest

from cwt import ClaimsBuilder


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return ClaimsBuilder()


class TestClaimsBuilder:
    """
    Tests for ClaimsBuilder.
    """

    def test_claims_builder_constructor(self):
        """"""
        c = ClaimsBuilder()
        assert isinstance(c, ClaimsBuilder)

    @pytest.mark.parametrize(
        "json, expected",
        [
            ({"iss": "coap://as.example.com"}, {1: "coap://as.example.com"}),
            ({"sub": "erikw"}, {2: "erikw"}),
            ({"aud": "coap://light.example.com"}, {3: "coap://light.example.com"}),
            ({"exp": 1444064944}, {4: 1444064944}),
            ({"nbf": 1443944944}, {5: 1443944944}),
            ({"iat": 1443944944}, {6: 1443944944}),
            ({"cti": "123"}, {7: b"123"}),
            ({}, {}),
        ],
    )
    def test_claims_builder_from_json(self, ctx, json, expected):
        """"""
        claims = ctx.from_json(json)
        for k, v in claims.items():
            assert v == expected[k]
            assert isinstance(v, type(expected[k]))
        len(claims) == len(expected)

    @pytest.mark.parametrize(
        "invalid",
        [
            {1: "coap://as.example.com"},
        ],
    )
    def test_claims_builder_from_json_with_invalid_arg(self, ctx, invalid):
        """"""
        with pytest.raises(ValueError) as err:
            res = ctx.from_json(invalid)
            pytest.fail("from_json should fail: res=%s" % res)
        assert "It is already CBOR-like format." in str(err.value)

    def test_claims_builder_from_json_with_unknown_key(self, ctx):
        """"""
        claims = ctx.from_json(
            {
                "iss": "coap://as.example.com",
                "unknown": "something",
            }
        )
        assert len(claims) == 1
        assert claims[1] == "coap://as.example.com"
