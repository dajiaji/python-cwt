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
            # Integrated Encryption
            COSEAlgs.HPKE_0,
            COSEAlgs.HPKE_1,
            COSEAlgs.HPKE_2,
            COSEAlgs.HPKE_3,
            COSEAlgs.HPKE_4,
            COSEAlgs.HPKE_5,
            COSEAlgs.HPKE_6,
            COSEAlgs.HPKE_7,
            # Key Encryption
            COSEAlgs.HPKE_0_KE,
            COSEAlgs.HPKE_1_KE,
            COSEAlgs.HPKE_2_KE,
            COSEAlgs.HPKE_3_KE,
            COSEAlgs.HPKE_4_KE,
            COSEAlgs.HPKE_5_KE,
            COSEAlgs.HPKE_6_KE,
            COSEAlgs.HPKE_7_KE,
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
