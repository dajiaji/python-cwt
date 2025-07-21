"""
Tests for HPKE.
"""

import pytest

from cwt.enums import COSEAlgs, COSEHeaders
from cwt.recipient_algs.hpke import HPKE


class TestHPKE:
    """
    Tests for HPKE.
    """

    @pytest.mark.parametrize(
        "alg",
        [
            COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
            COSEAlgs.HPKE_BASE_P256_SHA256_CHACHA20POLY1305,
            COSEAlgs.HPKE_BASE_P384_SHA384_AES256GCM,
            COSEAlgs.HPKE_BASE_P384_SHA384_CHACHA20POLY1305,
            COSEAlgs.HPKE_BASE_P521_SHA512_AES256GCM,
            COSEAlgs.HPKE_BASE_P521_SHA512_CHACHA20POLY1305,
            COSEAlgs.HPKE_BASE_X25519_SHA256_AES128GCM,
            COSEAlgs.HPKE_BASE_X25519_SHA256_CHACHA20POLY1305,
            COSEAlgs.HPKE_BASE_X448_SHA512_AES256GCM,
            COSEAlgs.HPKE_BASE_X448_SHA512_CHACHA20POLY1305,
        ],
    )
    def test_recipient_algs_hpke(self, alg):
        ctx = HPKE({COSEHeaders.ALG: alg}, {})
        assert isinstance(ctx, HPKE)
        assert ctx.alg == alg

    def test_recipient_algs_hpke_without_alg(self):
        with pytest.raises(ValueError) as err:
            HPKE({COSEHeaders.ALG: -1}, {})
            pytest.fail("HPKE should fail.")
        assert "alg should be one of the HPKE algorithms." in str(err.value)
