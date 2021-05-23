"""
Tests for utils
"""
import pytest

from cwt.utils import base64url_decode, i2osp, to_cis, uint_to_bytes


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

    def test_to_cis(self):
        res = to_cis(
            {
                "alg": "AES-CCM-16-64-128",
                "party_u": {
                    "identity": "lighting-client",
                    "nonce": "aabbccddeeff",
                    "other": "other PartyV info",
                },
                "party_v": {
                    "identity": "lighting-server",
                    "nonce": "112233445566",
                    "other": "other PartyV info",
                },
                "supp_pub": {
                    "key_data_length": 128,
                    "protected": {"alg": "direct+HKDF-SHA-256"},
                    "other": "Encryption Example 02",
                },
            }
        )
        assert isinstance(res, list)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {},
                "alg not found.",
            ),
            (
                {"alg": "xxx"},
                "Unsupported or unknown alg: xxx.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_u": 123},
                "party_u should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_u": {"identity": 123}},
                "party_u.identity should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_u": {"nonce": []}},
                "party_u.nonce should be str or int.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_u": {"nonce": 123, "other": 123}},
                "party_u.other should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_v": 123},
                "party_v should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_v": {"identity": 123}},
                "party_v.identity should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_v": {"nonce": []}},
                "party_v.nonce should be str or int.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "party_v": {"nonce": 123, "other": 123}},
                "party_v.other should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "supp_pub": 123},
                "supp_pub should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "supp_pub": {"key_data_length": "xxx"}},
                "supp_pub.key_data_length should be int.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "supp_pub": {"protected": "xxx"}},
                "supp_pub.protected should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "supp_pub": {"other": 123}},
                "supp_pub.other should be str.",
            ),
            (
                {"alg": "HS256"},
                "Unsupported or unknown alg: 5.",
            ),
            (
                {"alg": "HS256", "supp_pub": {}},
                "Unsupported or unknown alg: 5.",
            ),
        ],
    )
    def test_to_cis_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            to_cis(invalid)
            pytest.fail("cis should fail.")
        assert msg in str(err.value)
