# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for KeyBuilder.
"""
import pytest

from cwt import COSEKey, KeyBuilder, cose_key

from .utils import key_path

# from secrets import token_bytes


class TestKeyBuilder:
    """
    Tests for KeyBuilder.
    """

    def test_key_builder_constructor(self):
        """"""
        c = KeyBuilder()
        assert isinstance(c, KeyBuilder)

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
        kb = KeyBuilder()
        k = kb.from_symmetric_key("mysecretpassword", alg=alg)
        assert isinstance(k, COSEKey)

    def test_key_builder_from_symmetric_key_with_invalid_alg(self):
        """"""
        kb = KeyBuilder()
        with pytest.raises(ValueError) as err:
            res = kb.from_symmetric_key("mysecretpassword", alg="xxx")
            pytest.fail("from_symmetric_key should be fail: res=%s" % vars(res))
        assert "Unsupported or unknown alg" in str(err.value)

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.pem", "public_key_ed25519.pem"),
            ("private_key_ed448.pem", "public_key_ed448.pem"),
            ("private_key_es256.pem", "public_key_es256.pem"),
            ("private_key_es256k.pem", "public_key_es256k.pem"),
            ("private_key_es384.pem", "public_key_es384.pem"),
            ("private_key_es512.pem", "public_key_es512.pem"),
            ("private_key_x25519.pem", "public_key_x25519.pem"),
            ("private_key_x448.pem", "public_key_x448.pem"),
        ],
    )
    def test_cwt_encode_and_sign_with_valid_alg(
        self, private_key_path, public_key_path
    ):
        """"""
        try:
            with open(key_path(private_key_path)) as key_file:
                cose_key.from_pem(key_file.read())
            with open(key_path(public_key_path)) as key_file:
                cose_key.from_pem(key_file.read())
        except Exception as err:
            print(err)
            pytest.fail("from_pem should not fail.")
