"""
Tests for KeyWrap.
"""

import pytest

from cwt.algs.symmetric import AESKeyWrap
from cwt.enums import COSEAlgs, COSEKeyOps, COSEKeyParams, COSEKeyTypes
from cwt.exceptions import DecodeError


class TestAESKeyWrap:
    """
    Tests for AESKeyWrap.
    """

    def test_aes_key_wrap_constructor_a128kw(self):
        key = AESKeyWrap({COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128KW})
        assert key.alg == COSEAlgs.A128KW

    def test_aes_key_wrap_constructor_a192kw(self):
        key = AESKeyWrap({COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A192KW})
        assert isinstance(key, AESKeyWrap)
        assert key.alg == COSEAlgs.A192KW

    def test_aes_key_wrap_constructor_a256kw(self):
        key = AESKeyWrap({COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A256KW})
        assert isinstance(key, AESKeyWrap)
        assert key.alg == COSEAlgs.A256KW

    def test_aes_key_wrap_constructor_with_invalid_alg(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap({COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128GCM})
            pytest.fail("AESKeyWrap() should fail.")
        assert f"Unknown alg({COSEKeyParams.ALG}) for AES key wrap: {COSEAlgs.A128GCM}." in str(err.value)

    def test_aes_key_wrap_constructor_with_invalid_key_ops(self):
        with pytest.raises(ValueError) as err:
            AESKeyWrap(
                {
                    COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC,
                    COSEKeyParams.ALG: COSEAlgs.A128KW,
                    COSEKeyParams.KEY_OPS: [COSEKeyOps.SIGN, COSEKeyOps.VERIFY],
                }
            )
            pytest.fail("AESKeyWrap() should fail.")
        assert f"Unknown or not permissible key_ops({COSEKeyParams.KEY_OPS}) for AES key wrap: {COSEKeyOps.SIGN}." in str(
            err.value
        )

    def test_aes_key_wrap_unwrap_key_with_invalid_alg(self):
        key = AESKeyWrap({COSEKeyParams.KTY: COSEKeyTypes.ASYMMETRIC, COSEKeyParams.ALG: COSEAlgs.A128KW})
        with pytest.raises(DecodeError) as err:
            key.unwrap_key(b"")
            pytest.fail("unwrap_key() should fail.")
        assert "Failed to unwrap key." in str(err.value)
