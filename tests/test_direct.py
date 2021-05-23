"""
Tests for Direct.
"""
import pytest

from cwt.recipient_algs.direct import Direct, DirectKey


class TestDirect:
    """
    Tests for Direct.
    """

    def test_direct_constructor(self):
        ctx = Direct({1: -6}, {})
        assert isinstance(ctx, Direct)
        assert ctx.alg == -6
        assert ctx.kty == 4

    @pytest.mark.parametrize(
        "protected, unprotected, msg",
        [
            (
                {},
                {},
                "alg(1) not found.",
            ),
        ],
    )
    def test_direct_constructor_with_invalid_arg(self, protected, unprotected, msg):
        with pytest.raises(ValueError) as err:
            Direct(protected, unprotected)
            pytest.fail("Direct should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: -10},
                "alg(1) should be direct(-6).",
            ),
        ],
    )
    def test_direct_key_constructor_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            DirectKey(invalid)
            pytest.fail("Direct should fail.")
        assert msg in str(err.value)
