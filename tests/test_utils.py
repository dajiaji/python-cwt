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
                "apu": {
                    "id": "lighting-client",
                    "nonce": "aabbccddeeff",
                    "other": "other PartyV info",
                },
                "apv": {
                    "id": "lighting-server",
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

    def test_to_cis_without_supp_pub_other(self):
        res = to_cis(
            {
                "alg": "AES-CCM-16-64-128",
                "apu": {
                    "id": "lighting-client",
                    "nonce": "aabbccddeeff",
                    "other": "other PartyV info",
                },
                "apv": {
                    "id": "lighting-server",
                    "nonce": "112233445566",
                    "other": "other PartyV info",
                },
                "supp_pub": {
                    "key_data_length": 128,
                    "protected": {"alg": "direct+HKDF-SHA-256"},
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
                {"alg": "AES-CCM-16-64-128", "apu": 123},
                "apu should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apu": {"id": 123}},
                "apu.id should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apu": {"nonce": []}},
                "apu.nonce should be str or int.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apu": {"nonce": 123, "other": 123}},
                "apu.other should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apv": 123},
                "apv should be dict.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apv": {"id": 123}},
                "apv.id should be str.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apv": {"nonce": []}},
                "apv.nonce should be str or int.",
            ),
            (
                {"alg": "AES-CCM-16-64-128", "apv": {"nonce": 123, "other": 123}},
                "apv.other should be str.",
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
