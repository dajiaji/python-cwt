# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Claims.
"""
import pytest

from cwt.claims import Claims


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
                {8: "xxx"},
                "cnf(8) should be dict.",
            ),
            (
                {8: {0: {}}},
                "cnf(8) should include COSE_Key, Encrypted_COSE_Key, or kid.",
            ),
            (
                {8: {1: "xxx"}},
                "COSE_Key in cnf(8) should be dict.",
            ),
            (
                {8: {2: "xxx"}},
                "Encrypted_COSE_Key in cnf(8) should be list.",
            ),
            (
                {8: {3: "xxx"}},
                "kid in cnf(8) should be bytes.",
            ),
        ],
    )
    def test_claims_constructor_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            Claims(invalid)
            pytest.fail("Claims should fail.")
        assert msg in str(err.value)
