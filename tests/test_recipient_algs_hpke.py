"""
Tests for HPKE.
"""

import pytest

from cwt.enums import COSEHeaders
from cwt.recipient_algs.hpke import HPKE


class TestHPKE:
    """
    Tests for HPKE.
    """

    @pytest.mark.parametrize(
        "alg",
        [
            35,
            36,
            37,
            38,
            39,
            40,
            41,
            42,
            43,
            44,
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
