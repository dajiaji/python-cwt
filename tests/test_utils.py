"""
Tests for utils
"""
import pytest

from cwt.utils import base64url_decode, i2osp, uint_to_bytes


class TestUtils:
    """
    Tests for utils.
    """

    def test_utils_i2osp_invalid_arg(self):
        with pytest.raises(ValueError) as err:
            i2osp(270, 1)
            pytest.fail("i2osp should fail.")
        assert "integer too large" in str(err.value)

    def test_utils_uint_to_bytes_invalid_arg(self):
        with pytest.raises(ValueError) as err:
            uint_to_bytes(-1)
            pytest.fail("uint_to_bytes should fail.")
        assert "Not a positive number." in str(err.value)

    def test_base64url_decode_without_padding(self):
        res = base64url_decode("aaaabbbb")
        assert len(res) == 6
