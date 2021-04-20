# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Claims.
"""
import pytest

from cwt import Claims


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return Claims()


class TestKeyBuilder:
    """
    Tests for Claims.
    """

    def test_claims_constructor(self):
        """"""
        c = Claims()
        assert isinstance(c, Claims)

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
        ],
    )
    def test_claims_from_json(self, ctx, json, expected):
        """"""
        claims = ctx.from_json(json)
        for k, v in claims.items():
            assert v == expected[k]
            assert isinstance(v, type(expected[k]))
        len(claims) == len(expected)
