"""
Tests for RawKey.
"""
import pytest

from cwt.algs.raw import RawKey


class TestRawKey:
    """
    Tests for RawKey.
    """

    def test_raw_key_constructor(self):
        key = RawKey(
            {
                1: 4,
                -1: b"mysecret",
            }
        )
        assert key.key == b"mysecret"
        assert key.alg is None
        assert key.key_ops == []
        assert key.base_iv is None

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be Symmetric(4).",
            ),
            (
                {1: 4},
                "k(-1) should be set.",
            ),
            (
                {1: 4, -1: 123},
                "k(-1) should be bytes(bstr).",
            ),
        ],
    )
    def test_symmetric_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            RawKey(invalid)
            pytest.fail("SymmetricKey should fail.")
        assert msg in str(err.value)

    def test_raw_key_to_dict(self):
        key = RawKey(
            {
                1: 4,
                -1: b"mysecret",
            }
        )
        k = key.to_dict()
        assert k[1] == 4
        assert k[-1] == b"mysecret"
