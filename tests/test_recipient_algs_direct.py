"""
Tests for Direct.
"""

from secrets import token_bytes

import cbor2
import pytest

from cwt.cose_key import COSEKey
from cwt.exceptions import EncodeError, VerifyError
from cwt.recipient import Recipient
from cwt.recipient_algs.direct import Direct
from cwt.recipient_algs.direct_hkdf import DirectHKDF
from cwt.recipient_algs.direct_key import DirectKey
from cwt.utils import base64url_decode, to_recipient_context


class TestDirect:
    """
    Tests for Direct.
    """

    def test_direct_constructor(self):
        k = COSEKey.from_symmetric_key(alg="HS256")
        ctx = Direct({}, {1: -6})
        assert isinstance(ctx, Direct)
        assert ctx.alg == -6
        with pytest.raises(NotImplementedError):
            ctx.encode(k)
            pytest.fail("encode() should fail.")
        with pytest.raises(NotImplementedError):
            ctx.decode(k)
            pytest.fail("decode() should fail.")

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
            pytest.fail("Direct() should fail.")
        assert msg in str(err.value)


class TestDirectKey:
    """
    Tests for DirectKey.
    """

    def test_direct_key_constructor(self):
        ctx = DirectKey(unprotected={1: -6})
        assert isinstance(ctx, DirectKey)
        assert ctx.alg == -6

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
            pytest.fail("DirectKey() should fail.")
        assert msg in str(err.value)

    def test_direct_key_encode(self):
        k = COSEKey.from_symmetric_key(alg="HS256")
        ctx = DirectKey(unprotected={1: -6})
        _, derived_key = ctx.encode(k)
        assert derived_key is None

    def test_direct_key_encode_without_alg(self):
        ctx = DirectKey(unprotected={1: -6})
        encoded, derived_key = ctx.encode()
        assert isinstance(encoded, list)
        assert derived_key is None

    def test_direct_key_decode(self):
        k = COSEKey.from_symmetric_key(alg="HS256")
        ctx = DirectKey(unprotected={1: -6})
        decoded = ctx.decode(k, as_cose_key=True)
        assert decoded.alg == 5
        assert k.key == decoded.key


class TestDirectHKDF:
    """
    Tests for DirectHKDF.
    """

    def test_direct_hkdf_constructor_with_hkdf_sha_256(self):
        ctx = Recipient.new({1: -10}, {-20: b"aabbccddeeff"}, context={"alg": "A128GCM"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -10

    def test_direct_hkdf_constructor_with_party_u_nonce(self):
        ctx = Recipient.new({1: -10}, {-22: b"aabbccddeeff"}, context={"alg": "A128GCM"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -10

    def test_direct_hkdf_constructor_with_hkdf_sha_512(self):
        ctx = Recipient.new({1: -11}, {-20: b"aabbccddeeff"}, context={"alg": "A128GCM"})
        assert isinstance(ctx, DirectHKDF)
        assert ctx.alg == -11

    @pytest.mark.parametrize(
        "protected, unprotected, msg",
        [
            # (
            #     {1: -10},
            #     {},
            #     "salt(-20) or PartyU nonce(-22) should be set.",
            # ),
            (
                {1: -6},
                {-20: "aabbccddeeff"},
                "Unknown alg(3) for direct key with KDF: -6.",
            ),
        ],
    )
    def test_direct_hkdf_constructor_with_invalid_arg(self, protected, unprotected, msg):
        with pytest.raises(ValueError) as err:
            DirectHKDF(protected, unprotected, context={"alg": "A128GCM"})
            pytest.fail("DirectHKDF() should fail.")
        assert msg in str(err.value)

    def test_direct_hkdf_encode(self):
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        material = COSEKey.from_symmetric_key(token_bytes(16))
        ctx = DirectHKDF({1: -10}, {4: b"01", -20: b"aabbccddeeff"}, context=context)
        _, key = ctx.encode(material.to_bytes())
        assert key.alg == 10
        assert len(key.key) == 16

    def test_direct_hkdf_encode_without_salt(self):
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        material = COSEKey.from_symmetric_key(token_bytes(16))
        ctx = DirectHKDF({1: -10}, {4: b"01"}, context=context)
        _, key = ctx.encode(material.to_bytes())
        assert key.alg == 10
        assert len(key.key) == 16

    def test_direct_hkdf_encode_with_party_u_nonce(self):
        nonce = token_bytes(16)
        context = [
            10,
            [b"lighting-client", nonce, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        material = COSEKey.from_symmetric_key(token_bytes(16))
        ctx = DirectHKDF({1: -10}, {4: b"01"}, context=context)
        _, key = ctx.encode(material.to_bytes())
        assert key.alg == 10
        assert len(key.key) == 16
        assert nonce == ctx._unprotected[-22]

    def test_direct_hkdf_encode_with_party_v_nonce(self):
        nonce = token_bytes(16)
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", nonce, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        material = COSEKey.from_symmetric_key(token_bytes(16))
        ctx = DirectHKDF({1: -10}, {4: b"01"}, context=context)
        _, key = ctx.encode(material.to_bytes())
        assert key.alg == 10
        assert len(key.key) == 16
        assert nonce == ctx._unprotected[-25]

    # def test_direct_hkdf_encode_without_alg(self):
    #     material = COSEKey.from_symmetric_key(token_bytes(16))
    #     ctx = DirectHKDF(
    #         {1: -10},
    #         {4: b"01"},
    #         context={"alg": "A128GCM"},
    #     )
    #     with pytest.raises(ValueError) as err:
    #         ctx.encode(material.to_bytes())
    #         pytest.fail("encode() should fail.")
    #     assert "context should be set." in str(err.value)

    def test_direct_hkdf_encode_with_json_context(self):
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
        )
        ctx = Recipient.new(
            {1: -10},
            {-20: b"aabbccddeeff"},
            context={
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
        )
        _, key = ctx.encode(material.to_bytes())
        assert key.alg == 10

    # def test_direct_hkdf_encode_with_invalid_key(self):
    #     ctx = DirectHKDF(
    #         {1: -10},
    #         {-20: b"aabbccddeeff"},
    #         context={
    #             "alg": "AES-CCM-16-64-128",
    #             "party_u": {
    #                 "identity": "lighting-client",
    #             },
    #             "party_v": {
    #                 "identity": "lighting-server",
    #             },
    #             "supp_pub": {
    #                 "other": "Encryption Example 02",
    #             },
    #         },
    #     )
    #     with pytest.raises(EncodeError) as err:
    #         ctx.encode(
    #             plaintext=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
    #         )
    #         pytest.fail("encode() should fail.")
    #     assert "Failed to derive key." in str(err.value)

    def test_direct_hkdf_encode_with_invalid_material(self):
        ctx = Recipient.new(
            {1: -10},
            {-20: b"aabbccddeeff"},
            context={
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
        )
        with pytest.raises(EncodeError) as err:
            ctx.encode(plaintext=None)
            pytest.fail("encode() should fail.")
        assert "Failed to derive key." in str(err.value)

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
    def test_direct_hkdf_encode_with_invalid_context(self, invalid, msg):
        # material = COSEKey.from_symmetric_key(
        #     key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
        #     alg="A256GCM",
        # )
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -10}, {-20: b"aabbccddeeff"}, context=invalid)
            pytest.fail("DirectHKDF() should fail.")
        assert msg in str(err.value)

    def test_direct_hkdf_decode_with_raw_context(self):
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = Recipient.new({1: -10}, {-20: b"aabbccddeeff"}, context=context)
        decoded = ctx.decode(key, as_cose_key=True)
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
    def test_direct_hkdf_decode_with_json_context(self, alg, alg_id, key_len):
        key = COSEKey.from_symmetric_key(alg="A128GCM")
        ctx = Recipient.new({1: -10}, {-20: b"aabbccddeeff"}, context={"alg": alg})
        decoded = ctx.decode(key, as_cose_key=True)
        assert decoded.alg == alg_id
        assert len(decoded.key) == key_len

    def test_direct_hkdf_decode_with_invalid_context(self):
        # key = COSEKey.from_symmetric_key(alg="A128GCM")
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -10}, {-20: b"aabbccddeeff"}, context=[None, None, None])
            pytest.fail("DirectHKDF() should fail.")
        assert "Invalid context information." in str(err.value)

    def test_direct_hkdf_decode_without_context(self):
        # key = COSEKey.from_symmetric_key(alg="A128GCM")
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -10}, {-20: b"aabbccddeeff"})
            pytest.fail("DirectHKDF() should fail.")
        assert "context should be set." in str(err.value)

    def test_direct_hkdf_decode_with_invalid_key(self):
        # key = COSEKey.from_symmetric_key(key="a", alg="HS256")
        with pytest.raises(ValueError) as err:
            Recipient.new({1: -10}, {-20: b"aabbccddeeff"})
            pytest.fail("DirectHKDF() should fail.")
        assert "context should be set." in str(err.value)

    def test_direct_hkdf_verify_key(self):
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
        )
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
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"}, context=to_recipient_context(-10, {-20: b"aabbccddeeff"}, context))
        _, key = ctx.encode(material.to_bytes())
        ctx.verify_key(
            base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            key.key,
        )

    def test_direct_hkdf_verify_key_with_raw_context(self):
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
        )
        context = [
            10,
            [b"lighting-client", None, None],
            [b"lighting-server", None, None],
            [128, cbor2.dumps({1: -10}), b"Encryption Example 02"],
        ]
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"}, context=context)
        _, key = ctx.encode(material.to_bytes())
        ctx.verify_key(
            base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            key.key,
        )

    def test_direct_hkdf_verify_key_with_invalid_material(self):
        material = COSEKey.from_symmetric_key(
            key=base64url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
            alg="A256GCM",
        )
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
        ctx = DirectHKDF({1: -10}, {-20: b"aabbccddeeff"}, context=to_recipient_context(-10, {-20: b"aabbccddeeff"}, context))
        _, key = ctx.encode(material.to_bytes())
        with pytest.raises(VerifyError) as err:
            ctx.verify_key(
                b"xxxxxxxxxx",
                key.key,
            )
            pytest.fail("verify_key() should fail.")
        assert "Failed to verify key." in str(err.value)
