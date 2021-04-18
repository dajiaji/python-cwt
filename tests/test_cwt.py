# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for CWT.
"""
# import cbor2
import pytest

# from secrets import token_bytes

from cwt import CWT, claims, cose_key, VerifyError

# from .utils import key_path


class TestCWT:
    """
    Tests for CWT.
    """

    def test_cwt_constructor(self):
        """"""
        c = CWT()
        assert isinstance(c, CWT)

    def test_cwt_encode_and_mac_with_default_alg(self):
        """"""
        c = CWT()
        key = cose_key.from_symmetric_key("mysecretpassword")
        token = c.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        decoded = c.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 2 in decoded and decoded[7] == b"123"

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
        ],
    )
    def test_cwt_encode_and_mac_with_valid_alg(self, alg):
        """"""
        c = CWT()
        key = cose_key.from_symmetric_key("mysecretpassword", alg=alg)
        token = c.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        decoded = c.decode(token, key)
        assert 1 in decoded and decoded[1] == "https://as.example"
        assert 2 in decoded and decoded[2] == "someone"
        assert 2 in decoded and decoded[7] == b"123"

    def test_cwt_decode_with_invalid_mac_key(self):
        """"""
        c = CWT()
        key = cose_key.from_symmetric_key("mysecretpassword")
        token = c.encode_and_mac(
            {1: "https://as.example", 2: "someone", 7: b"123"}, key
        )
        wrong_key = cose_key.from_symmetric_key("xxxxxxxxxx")
        with pytest.raises(VerifyError) as err:
            res = c.decode(token, wrong_key)
            pytest.fail("decode should be fail: res=%s" % vars(res))
        assert "Failed to compare digest" in str(err.value)
