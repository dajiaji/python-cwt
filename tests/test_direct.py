"""
Tests for Direct.
"""
import cbor2
import pytest

from cwt.cose_key import COSEKey
from cwt.exceptions import EncodeError, VerifyError
from cwt.recipient_algs.direct import Direct
from cwt.recipient_algs.direct_hkdf import DirectHKDF
from cwt.recipient_algs.direct_key import DirectKey


class TestDirect:
    """
    Tests for Direct.
    """

    def test_direct_constructor(self):
        ctx = Direct({1: -6}, {})
        assert isinstance(ctx, Direct)
        assert ctx.alg == -6

    @pytest.mark.parametrize(
        "protected, unprotected, msg",
        [
            (
                {},
                {},
                "alg(1) not found.",
            ),
        ],
    )
    def test_direct_constructor_with_invalid_arg(self, protected, unprotected, msg):
        with pytest.raises(ValueError) as err:
            Direct(protected, unprotected)
            pytest.fail("Direct should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: -10},
                "alg(1) should be direct(-6).",
            ),
        ],
    )
    def test_direct_key_constructor_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            DirectKey(invalid)
            pytest.fail("Direct should fail.")
        assert msg in str(err.value)


class TestDirectHKDF:
    """
    Tests for DirectHKDF.
    """

    def test_direct_hkdf_constructor_with_hkdf_sha_256(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -10

    def test_direct_hkdf_constructor_with_party_u_nonce(self):
        ctx = DirectHKDF({1: -10}, {-22: b"aabbccddeeff"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -10

    def test_direct_hkdf_constructor_with_hkdf_sha_512(self):
        ctx = DirectHKDF({1: -11}, {-20: b"aabbccddeeff"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -11

    def test_direct_hkdf_decode_key_with_raw_context(self):
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        decoded = ctx.decode_key(key, context=context)
        assert decoded.alg == 10
        assert len(decoded.key) == 16

    @pytest.mark.parametrize(
        "alg, alg_id, key_len",
        [
            ("AES-CCM-16-64-128", 10, 16),
            ("AES-CCM-16-64-256", 11, 32),
            ("AES-CCM-64-64-128", 12, 16),
            ("AES-CCM-64-64-256", 13, 32),
        ],
    )
    def test_direct_hkdf_decode_key_with_json_context(self, alg, alg_id, key_len):
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        decoded = ctx.decode_key(key, context={"alg": alg})
        assert decoded.alg == alg_id
        assert len(decoded.key) == key_len

    def test_direct_hkdf_decode_key_without_context(self):
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        with pytest.raises(ValueError) as err:
            ctx.decode_key(key, alg="A128GCM")
            pytest.fail("decode_key() should fail.")
        assert "context should be set." in str(err.value)

    def test_direct_hkdf_decode_key_with_invalid_key(self):
        key = COSEKey.from_symmetric_key(key="a", alg="HS256")
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        with pytest.raises(ValueError) as err:
            ctx.decode_key(key, alg="A128GCM")
            pytest.fail("decode_key() should fail.")
        assert "context should be set." in str(err.value)

    @pytest.mark.parametrize(
        "protected, unprotected, msg",
        [
            (
                {1: -10},
                {},
                "salt(-20) or PartyU nonce(-22) should be set.",
            ),
            (
                {1: -6},
                {-20: "aabbccddeeff"},
                "Unknown alg(3) for direct key with KDF: -6.",
            ),
        ],
    )
    def test_direct_hkdf_constructor_with_invalid_arg(
        self, protected, unprotected, msg
    ):
        with pytest.raises(ValueError) as err:
            DirectHKDF(protected, unprotected)
            pytest.fail("Direct should fail.")
        assert msg in str(err.value)

    def test_direct_hkdf_derive_key(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        key = ctx.derive_key(
            {
                "alg": "AES-CCM-16-64-128",
                "party_u": {
                    "identity": "lighting-client",
                },
                "party_v": {
                    "identity": "lighting-server",
                },
                "supp_pub": {
                    "other": "Encryption Example 02",
                },
            },
            material=b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        )
        assert key.alg == 10

    def test_direct_hkdf_derive_key_with_invalid_material(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        with pytest.raises(EncodeError) as err:
            ctx.derive_key(
                {
                    "alg": "AES-CCM-16-64-128",
                    "party_u": {
                        "identity": "lighting-client",
                    },
                    "party_v": {
                        "identity": "lighting-server",
                    },
                    "supp_pub": {
                        "other": "Encryption Example 02",
                    },
                },
                None,
            )
            pytest.fail("derive_key should fail.")
        assert "Failed to derive key." in str(err.value)

    def test_direct_hkdf_verify_key(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        context = {
            "alg": "AES-CCM-16-64-128",
            "party_u": {
                "identity": "lighting-client",
            },
            "party_v": {
                "identity": "lighting-server",
            },
            "supp_pub": {
                "other": "Encryption Example 02",
            },
        }
        key = ctx.derive_key(
            context,
            material=b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        )
        ctx.verify_key(
            b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            key.key,
            context=context,
        )

    def test_direct_hkdf_verify_key_with_raw_context(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        key = ctx.derive_key(
            context,
            material=b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        )
        ctx.verify_key(
            b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            key.key,
            context=context,
        )

    def test_direct_hkdf_verify_key_with_invalid_material(self):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        context = {
            "alg": "AES-CCM-16-64-128",
            "party_u": {
                "identity": "lighting-client",
            },
            "party_v": {
                "identity": "lighting-server",
            },
            "supp_pub": {
                "other": "Encryption Example 02",
            },
        }
        key = ctx.derive_key(
            context,
            material=b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        )
        with pytest.raises(VerifyError) as err:
            ctx.verify_key(
                b"xxxxxxxxxx",
                key.key,
                context=context,
            )
            pytest.fail("verify_key should fail.")
        assert "Failed to verify key." in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                [],
                "Invalid context information.",
            ),
            (
                ["xxxx", [], [], []],
                "AlgorithmID should be int.",
            ),
            (
                [-6, [], [], []],
                "Unsupported or unknown algorithm: -6.",
            ),
            (
                [10, {}, [], []],
                "PartyUInfo should be list(size=3).",
            ),
            (
                [10, [None, None, None], {}, []],
                "PartyVInfo should be list(size=3).",
            ),
            (
                [10, [None, None, None], [None, None, None], {}],
                "SuppPubInfo should be list(size=2 or 3).",
            ),
        ],
    )
    def test_direct_hkdf_derive_key_with_invalid_context(self, invalid, msg):
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"})
        with pytest.raises(ValueError) as err:
            ctx.derive_key(
                invalid,
                material=b"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            )
            pytest.fail("derive_key should fail.")
        assert msg in str(err.value)
