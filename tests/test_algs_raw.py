"""
Tests for RawKey.
"""

import pytest

from cwt.algs.raw import RawKey
from cwt.enums import COSEKeyParams, COSEKeyTypes


class TestRawKey:
    """
    Tests for RawKey.
    """

    def test_raw_key_constructor(self):
        key = RawKey(
            {
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
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
                {COSEKeyParams.KTY: COSEKeyTypes.EC2},
                f"kty({COSEKeyParams.KTY}) should be Symmetric({COSEKeyTypes.ASYMMETRIC}).",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC},
                f"k({COSEKeyParams.K}) should be set.",
            ),
            (
                {COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.K: 123},
                f"k({COSEKeyParams.K}) should be bytes(bstr).",
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
                COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                COSEKeyParams.K: b"mysecret",
            }
        )
        k = key.to_dict()
        assert k[COSEKeyParams.KTY] == COSEKeyTypes.ASYMMETRIC
        assert k[COSEKeyParams.K] == b"mysecret"
