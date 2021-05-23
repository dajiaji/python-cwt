# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Recipient.
"""
import cbor2
import pytest

from cwt import Recipient, cose_key, recipient_builder
from cwt.recipient_builder import RecipientBuilder
from cwt.recipients import Recipients
from cwt.recipients_builder import RecipientsBuilder


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return Recipient()


@pytest.fixture(scope="session", autouse=True)
def material():
    return {
        "kid": "02",
        "value": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        "context": {
            "alg": "AES-CCM-16-64-128",
            "party_v": {
                "identity": "lighting-client",
                "nonce": "aabbccddeeff",
                "other": "other PartyV info",
            },
            "party_u": {
                "identity": "lighting-server",
                "nonce": "112233445566",
                "other": "other PartyV info",
            },
            "supp_pub": {
                "key_data_length": 128,
                "protected": {"alg": "direct+HKDF-SHA-256"},
                "other": "Encryption Example 02",
            },
        },
    }


class TestRecipient:
    """
    Tests for Recipient.
    """

    def test_recipient_constructor(self):
        r = Recipient()
        assert isinstance(r, Recipient)
        assert r.protected == {}
        assert r.unprotected == {}
        assert r.ciphertext == b""
        assert isinstance(r.recipients, list)
        assert r.kid == b""
        assert r.alg == 0
        assert len(r.recipients) == 0
        with pytest.raises(NotImplementedError):
            r.derive_key(b"", [])
            pytest.fail("derive_key should fail.")
        with pytest.raises(NotImplementedError):
            r.verify_key(b"", b"", [])
            pytest.fail("verify_key should fail.")
        res = r.to_list()
        assert len(res) == 3
        assert res[0] == b""
        assert isinstance(res[1], dict)
        assert res[2] == b""

    def test_recipient_constructor_with_args(self):
        child = Recipient(unprotected={1: -6, 4: b"our-secret"})
        r = Recipient(
            protected={"foo": "bar"},
            unprotected={1: -1, 4: b"our-secret"},
            recipients=[child],
        )
        assert isinstance(r.protected, dict)
        assert r.protected["foo"] == "bar"
        assert isinstance(r.unprotected, dict)
        assert r.kid == b"our-secret"
        assert r.alg == -1
        assert r.ciphertext == b""
        assert len(r.recipients) == 1
        res = r.to_list()
        assert len(res) == 4
        assert isinstance(res[3], list)
        assert len(res[3]) == 1
        assert isinstance(res[3][0], list)
        assert len(res[3][0]) == 3

    def test_recipient_constructor_with_empty_recipients(self):
        r = Recipient(unprotected={1: -6, 4: b"our-secret"}, recipients=[])
        assert isinstance(r, Recipient)
        assert r.protected == {}
        assert isinstance(r.unprotected, dict)
        assert r.ciphertext == b""
        assert len(r.recipients) == 0
        res = r.to_list()
        assert len(res) == 3

    def test_recipient_constructor_with_alg_a128kw(self):
        r = Recipient(protected={1: -3}, unprotected={4: b"our-secret"})
        assert isinstance(r, Recipient)
        assert r.alg == -3
        assert isinstance(r.protected, dict)
        assert isinstance(r.unprotected, dict)
        assert r.ciphertext == b""
        assert len(r.recipients) == 0
        res = r.to_list()
        assert len(res) == 3

    def test_recipient_constructor_with_alg_a128kw_with_iv(self):
        r = Recipient(
            protected={1: -3}, unprotected={4: b"our-secret", 5: b"aabbccddee"}
        )
        assert isinstance(r, Recipient)
        assert r.alg == -3
        assert r.base_iv == b"aabbccddee"
        assert isinstance(r.protected, dict)
        assert isinstance(r.unprotected, dict)
        assert r.ciphertext == b""
        assert len(r.recipients) == 0
        res = r.to_list()
        assert len(res) == 3

    @pytest.mark.parametrize(
        "protected, unprotected, ciphertext, recipients, msg",
        [
            (
                {"foo": "bar"},
                {1: -6, 4: b"our-secret"},
                b"",
                [],
                "protected header should be empty.",
            ),
            (
                {},
                {1: -6, 4: b"our-secret"},
                b"xxx",
                [],
                "ciphertext should be zero-length bytes.",
            ),
            (
                {},
                {1: -6, 4: b"our-secret"},
                b"",
                [Recipient()],
                "recipients should be absent.",
            ),
            (
                {},
                {4: "our-secret"},
                b"",
                [Recipient()],
                "unprotected[4](kid) should be bytes.",
            ),
            (
                {1: "alg-a"},
                {4: b"our-secret"},
                b"",
                [Recipient()],
                "protected[1](alg) should be int.",
            ),
            (
                {},
                {1: "alg-a", 4: b"our-secret"},
                b"",
                [Recipient()],
                "unprotected[1](alg) should be int.",
            ),
            (
                {},
                {4: b"our-secret", 5: "xxx"},
                b"",
                [Recipient()],
                "unprotected[5](iv) should be bytes.",
            ),
        ],
    )
    def test_recipient_constructor_with_invalid_args(
        self, protected, unprotected, ciphertext, recipients, msg
    ):
        with pytest.raises(ValueError) as err:
            Recipient(protected, unprotected, ciphertext, recipients)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)

    def test_recipient_constructor_with_invalid_recipients(self):
        child = {}
        with pytest.raises(ValueError) as err:
            Recipient(unprotected={1: 0, 4: b"our-secret"}, recipients=[child])
            pytest.fail("Recipient() should fail.")
        assert "Invalid child recipient." in str(err.value)


class TestRecipientBuilder:
    """
    Tests for RecipientBuilder.
    """

    @pytest.mark.parametrize(
        "protected, unprotected, msg",
        [
            (
                {},
                {},
                "alg should be specified.",
            ),
            (
                {1: -65535},
                {},
                "Unsupported or unknown alg(1): -65535.",
            ),
        ],
    )
    def test_recipient_builder_from_dict_with_invalid_arg(
        self, protected, unprotected, msg
    ):
        ctx = RecipientBuilder()
        with pytest.raises(ValueError) as err:
            ctx.from_dict(protected, unprotected)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)

    def test_recipient_builder_from_json_with_str(self):
        ctx = RecipientBuilder()
        recipient = ctx.from_json('{"alg": "direct"}')
        assert isinstance(recipient, Recipient)
        assert recipient.alg == -6

    @pytest.mark.parametrize(
        "data, msg",
        [
            (
                {"foo": "bar"},
                "alg should be specified.",
            ),
            (
                {"alg": "xxx"},
                "Unsupported or unknown alg: xxx.",
            ),
            (
                {"alg": 123},
                "alg should be str.",
            ),
            (
                {"kid": 123},
                "kid should be str.",
            ),
            (
                {"salt": 123},
                "salt should be str.",
            ),
        ],
    )
    def test_recipient_builder_from_json_with_invalid_arg(self, data, msg):
        ctx = RecipientBuilder()
        with pytest.raises(ValueError) as err:
            ctx.from_json(data)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)


class TestRecipients:
    """
    Tests for Recipients.
    """

    def test_recipients_constructor(self):
        r = Recipients([Recipient()])
        assert isinstance(r, Recipients)

    def test_recipients_constructor_with_recipient_alg_direct(self):
        key = cose_key.from_symmetric_key(
            "mysecret", alg="HMAC 256/64", kid="our-secret"
        )
        r = Recipients([Recipient(unprotected={1: -6, 4: b"our-secret"})])
        key = r.derive_key([key])
        assert key.kty == 4
        assert key.alg == 4
        assert key.kid == b"our-secret"

    def test_recipients_derive_key_with_empty_recipient(self):
        key = cose_key.from_symmetric_key(
            "mysecret", alg="HMAC 256/64", kid="our-secret"
        )
        r = Recipients([Recipient()])
        with pytest.raises(ValueError) as err:
            r.derive_key([key])
            pytest.fail("derive_key() should fail.")
        assert "Failed to derive a key." in str(err.value)

    def test_recipients_derive_key_without_key(self):
        r = Recipients([Recipient(unprotected={1: -6, 4: b"our-secret"})])
        with pytest.raises(ValueError) as err:
            r.derive_key([])
            pytest.fail("derive_key() should fail.")
        assert "Failed to derive a key." in str(err.value)

    def test_recipients_derive_key_without_args(self):
        r = Recipients([Recipient(unprotected={1: -6, 4: b"our-secret"})])
        with pytest.raises(ValueError) as err:
            r.derive_key()
            pytest.fail("derive_key() should fail.")
        assert "Either keys or materials should be specified." in str(err.value)

    def test_recipients_derive_key_with_empty_recipients(self, material):
        r = Recipients([])
        with pytest.raises(ValueError) as err:
            r.derive_key(materials=[material])
            pytest.fail("derive_key() should fail.")
        assert "Failed to derive a key." in str(err.value)

    def test_recipients_derive_key_with_multiple_recipients(self, material):
        r1 = recipient_builder.from_json(
            {
                "alg": "direct",
                "kid": "01",
            }
        )
        r2 = recipient_builder.from_json(
            {
                "alg": "direct+HKDF-SHA-256",
                "kid": "02",
                "salt": "aabbccddeeffgghh",
            }
        )
        rs = Recipients([r1, r2])
        key = rs.derive_key(materials=[material])
        assert key.alg == 10
        assert key.kid == b"02"

    def test_recipients_derive_key_with_different_kid(self):
        key = cose_key.from_symmetric_key(
            "mysecret", alg="HMAC 256/64", kid="our-secret"
        )
        r = Recipients([Recipient(unprotected={1: -6, 4: b"your-secret"})])
        with pytest.raises(ValueError) as err:
            r.derive_key([key])
            pytest.fail("derive_key() should fail.")
        assert "Failed to derive a key." in str(err.value)


class TestRecipientsBuilder:
    """
    Tests for RecipientsBuilder.
    """

    def test_recipients_builder_constructor(self):
        rb = RecipientsBuilder()
        assert isinstance(rb, RecipientsBuilder)

    def test_recipients_builder_from_list(self):
        rb = RecipientsBuilder()
        try:
            rb.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b""]])
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_builder_from_list_with_empty_recipients(self):
        rb = RecipientsBuilder()
        try:
            rb.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b"", []]])
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_builder_from_list_with_recipients(self):
        rb = RecipientsBuilder()
        try:
            rb.from_list(
                [
                    [
                        cbor2.dumps({1: -10}),
                        {-20: b"aabbccddeefff"},
                        b"",
                        [[b"", {1: -6, 4: b"our-secret"}, b""]],
                    ]
                ]
            )
        except Exception:
            pytest.fail("from_list() should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ([{}], "Invalid recipient format."),
            ([123], "Invalid recipient format."),
            ([[]], "Invalid recipient format."),
            ([[b"", {}]], "Invalid recipient format."),
            ([[b"", {}, b"", [], {}]], "Invalid recipient format."),
            ([["", {}, b""]], "protected header should be bytes."),
            ([[{}, {}, b""]], "protected header should be bytes."),
            ([[[], {}, b""]], "protected header should be bytes."),
            ([[123, {}, b""]], "protected header should be bytes."),
            ([[b"", [], b""]], "unprotected header should be dict."),
            ([[b"", "", b""]], "unprotected header should be dict."),
            ([[b"", b"", b""]], "unprotected header should be dict."),
            ([[b"", 123, b""]], "unprotected header should be dict."),
            ([[b"", {}, ""]], "ciphertext should be bytes."),
            ([[b"", {}, {}]], "ciphertext should be bytes."),
            ([[b"", {}, []]], "ciphertext should be bytes."),
            ([[b"", {}, 123]], "ciphertext should be bytes."),
            ([[b"", {}, b"", {}]], "recipients should be list."),
            ([[b"", {}, b"", ""]], "recipients should be list."),
            ([[b"", {}, b"", b""]], "recipients should be list."),
            ([[b"", {}, b"", 123]], "recipients should be list."),
        ],
    )
    def test_recipients_builder_from_list_with_invalid_args(self, invalid, msg):
        rb = RecipientsBuilder()
        with pytest.raises(ValueError) as err:
            rb.from_list(invalid)
            pytest.fail("derive_key() should fail.")
        assert msg in str(err.value)
