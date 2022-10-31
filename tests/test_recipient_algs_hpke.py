"""
Tests for HPKE.
"""

import pytest

from cwt.recipient_algs.hpke import HPKE


class TestHPKE:
    """
    Tests for HPKE.
    """

    def test_recipient_algs_hpke(self):
        ctx = HPKE({1: -1}, {-4: {1: 0x0010, 2: 0x0001, 3: 0x0001}})
        assert isinstance(ctx, HPKE)
        assert ctx.alg == -1

    def test_recipient_algs_hpke_apply_without_recipient_key(self):
        ctx = HPKE({1: -1}, {-4: {1: 0x0010, 2: 0x0001, 3: 0x0001}})
        with pytest.raises(ValueError) as err:
            ctx.apply()
            pytest.fail("apply should fail.")
        assert "recipient_key should be set." in str(err.value)

    def test_recipient_algs_hpke_without_alg(self):
        with pytest.raises(ValueError) as err:
            HPKE({1: 1}, {-4: {1: 0x0010, 2: 0x0001, 3: 0x0001}})
            pytest.fail("HPKE should fail.")
        assert "alg should be HPKE(-1)." in str(err.value)

    @pytest.mark.parametrize(
        "hsi, msg",
        [
            (
                {},
                "HPKE sender information(-4) not found.",
            ),
            (
                {-4: {2: 0x0001, 3: 0x0001}},
                "kem id(1) not found in HPKE sender information(-4).",
            ),
            (
                {-4: {1: 0x0010, 3: 0x0001}},
                "kdf id(2) not found in HPKE sender information(-4).",
            ),
            (
                {-4: {1: 0x0010, 2: 0x0001}},
                "aead id(3) not found in HPKE sender information(-4).",
            ),
            (
                {-4: {1: 0xFFFF, 2: 0x0001, 3: 0x0001}},
                "Unsupported or unknown KEM id: 65535.",
            ),
            (
                {-4: {1: 0x0010, 2: 0xFFFF, 3: 0x0001}},
                "Unsupported or unknown KDF id: 65535.",
            ),
            (
                {-4: {1: 0x0010, 2: 0x0001, 3: 0xFFFF}},
                "Unsupported or unknown AEAD id: 65535.",
            ),
        ],
    )
    def test_recipient_algs_hpke_with_invalid_hsi(self, hsi, msg):
        with pytest.raises(ValueError) as err:
            HPKE({1: -1}, hsi)
            pytest.fail("HPKE should fail.")
        assert msg in str(err.value)
