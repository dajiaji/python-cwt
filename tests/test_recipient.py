# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Recipient.
"""
import cbor2
import pytest

from cwt import COSEKey, Recipient
from cwt.recipient_interface import RecipientInterface
from cwt.recipients import Recipients


@pytest.fixture(scope="session", autouse=True)
def ctx():
    return RecipientInterface()


@pytest.fixture(scope="session", autouse=True)
def material():
    return COSEKey.from_symmetric_key(alg="A256GCM", kid="02")


@pytest.fixture(scope="session", autouse=True)
def context():
    return {
        "alg": "AES-CCM-16-64-128",
        "apv": {
            "identity": "lighting-client",
            "nonce": "aabbccddeeff",
            "other": "other PartyV info",
        },
        "apu": {
            "identity": "lighting-server",
            "nonce": "112233445566",
            "other": "other PartyV info",
        },
        "supp_pub": {
            "key_data_length": 128,
            "protected": {"alg": "direct+HKDF-SHA-256"},
            "other": "Encryption Example 02",
        },
    }


class TestRecipientInterface:
    """
    Tests for RecipientInterface.
    """

    def test_recipient_constructor(self):
        k = COSEKey.from_symmetric_key(alg="A256GCM")
        r = RecipientInterface()
        assert isinstance(r, RecipientInterface)
        assert r.protected == {}
        assert r.unprotected == {}
        assert r.ciphertext == b""
        assert isinstance(r.recipients, list)
        assert r.kid == b""
        assert r.alg == 0
        assert len(r.recipients) == 0
        with pytest.raises(NotImplementedError):
            r.apply(k)
            pytest.fail("apply() should fail.")
        with pytest.raises(NotImplementedError):
            r.extract(k)
            pytest.fail("extract() should fail.")
        res = r.to_list()
        assert len(res) == 3
        assert res[0] == b""
        assert isinstance(res[1], dict)
        assert res[2] == b""

    def test_recipient_constructor_with_args(self):
        child = RecipientInterface(unprotected={1: -6, 4: b"our-secret"})
        r = RecipientInterface(
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
        r = RecipientInterface(unprotected={1: -6, 4: b"our-secret"}, recipients=[])
        assert isinstance(r, RecipientInterface)
        assert r.protected == {}
        assert isinstance(r.unprotected, dict)
        assert r.ciphertext == b""
        assert len(r.recipients) == 0
        res = r.to_list()
        assert len(res) == 3

    def test_recipient_constructor_with_alg_a128kw(self):
        r = RecipientInterface(protected={1: -3}, unprotected={4: b"our-secret"})
        assert isinstance(r, RecipientInterface)
        assert r.alg == -3
        assert isinstance(r.protected, dict)
        assert isinstance(r.unprotected, dict)
        assert r.ciphertext == b""
        assert len(r.recipients) == 0
        res = r.to_list()
        assert len(res) == 3

    def test_recipient_constructor_with_alg_a128kw_with_iv(self):
        r = RecipientInterface(protected={1: -3}, unprotected={4: b"our-secret", 5: b"aabbccddee"})
        assert isinstance(r, RecipientInterface)
        assert r.alg == -3
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
                [RecipientInterface()],
                "recipients should be absent.",
            ),
            (
                {},
                {4: "our-secret"},
                b"",
                [RecipientInterface()],
                "unprotected[4](kid) should be bytes.",
            ),
            (
                {4: "our-secret"},
                {},
                b"",
                [RecipientInterface()],
                "protected[4](kid) should be bytes.",
            ),
            (
                {1: "alg-a"},
                {4: b"our-secret"},
                b"",
                [RecipientInterface()],
                "protected[1](alg) should be int.",
            ),
            (
                {},
                {1: "alg-a", 4: b"our-secret"},
                b"",
                [RecipientInterface()],
                "unprotected[1](alg) should be int.",
            ),
            (
                {},
                {4: b"our-secret", 5: "xxx"},
                b"",
                [RecipientInterface()],
                "unprotected[5](iv) should be bytes.",
            ),
        ],
    )
    def test_recipient_constructor_with_invalid_args(self, protected, unprotected, ciphertext, recipients, msg):
        with pytest.raises(ValueError) as err:
            RecipientInterface(protected, unprotected, ciphertext, recipients)
            pytest.fail("RecipientInterface() should fail.")
        assert msg in str(err.value)

    def test_recipient_constructor_with_invalid_recipients(self):
        child = {}
        with pytest.raises(ValueError) as err:
            RecipientInterface(unprotected={1: 0, 4: b"our-secret"}, recipients=[child])
            pytest.fail("RecipientInterface() should fail.")
        assert "Invalid child recipient." in str(err.value)


class TestRecipient:
    """
    Tests for Recipient.
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
    def test_recipient_new_with_invalid_arg(self, protected, unprotected, msg):
        with pytest.raises(ValueError) as err:
            Recipient.new(protected, unprotected)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)

    def test_recipient_from_jwk_with_str(self):
        recipient = Recipient.from_jwk('{"alg": "direct"}')
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -6

    def test_recipient_from_jwk_with_dict(self):
        recipient = Recipient.from_jwk({"kty": "oct", "alg": "A128KW", "key_ops": ["wrapKey"]})
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -3

    def test_recipient_from_jwk_with_dict_and_with_byte_formatted_kid(self):
        recipient = Recipient.from_jwk({"kty": "oct", "kid": b"01", "alg": "A128KW", "key_ops": ["wrapKey"]})
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -3
        assert recipient.kid == b"01"

    def test_recipient_from_jwk_with_context(self):
        recipient = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "context": {
                    "apu": {
                        "id": "sender-01",
                        "nonce": "xxx",
                        "other": "yyy",
                    },
                    "apv": {
                        "id": "recipient-01",
                        "nonce": "abc",
                        "other": "def",
                    },
                },
            }
        )
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -10
        assert recipient._unprotected[-21] == b"sender-01"
        assert recipient._unprotected[-22] == b"xxx"
        assert recipient._unprotected[-23] == b"yyy"
        assert recipient._unprotected[-24] == b"recipient-01"
        assert recipient._unprotected[-25] == b"abc"
        assert recipient._unprotected[-26] == b"def"

    def test_recipient_from_jwk_with_context_id(self):
        recipient = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "context": {
                    "apu": {
                        "id": "sender-01",
                    },
                    "apv": {
                        "id": "recipient-01",
                    },
                },
            }
        )
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -10
        assert recipient._unprotected[-21] == b"sender-01"
        assert -22 not in recipient._unprotected
        assert -23 not in recipient._unprotected
        assert recipient._unprotected[-24] == b"recipient-01"
        assert -25 not in recipient._unprotected
        assert -26 not in recipient._unprotected

    def test_recipient_from_jwk_with_context_nonce(self):
        recipient = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "context": {
                    "apu": {
                        "nonce": "xxx",
                    },
                    "apv": {
                        "nonce": "abc",
                    },
                },
            }
        )
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -10
        assert -21 not in recipient._unprotected
        assert recipient._unprotected[-22] == b"xxx"
        assert -23 not in recipient._unprotected
        assert -24 not in recipient._unprotected
        assert recipient._unprotected[-25] == b"abc"
        assert -26 not in recipient._unprotected

    def test_recipient_from_jwk_with_context_other(self):
        recipient = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "context": {
                    "apu": {
                        "other": "yyy",
                    },
                    "apv": {
                        "other": "def",
                    },
                },
            }
        )
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -10
        assert -21 not in recipient._unprotected
        assert -22 not in recipient._unprotected
        assert recipient._unprotected[-23] == b"yyy"
        assert -24 not in recipient._unprotected
        assert -25 not in recipient._unprotected
        assert recipient._unprotected[-26] == b"def"

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
                {"alg": "direct", "kid": 123},
                "kid should be str or bytes.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "kid": 123},
                "kid should be str or bytes.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "salt": 123},
                "salt should be str.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "key_ops": 123},
                "key_ops should be list.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "key_ops": [123]},
                "Unsupported or unknown key_ops.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "key_ops": ["xxx"]},
                "Unsupported or unknown key_ops.",
            ),
            (
                {"kty": "oct", "alg": "A128KW", "k": 123},
                "k should be str.",
            ),
            (
                {"kty": "oct", "alg": "direct+HKDF-SHA-256", "context": []},
                "context should be dict.",
            ),
        ],
    )
    def test_recipient_from_jwk_with_invalid_arg(self, data, msg):
        with pytest.raises(ValueError) as err:
            Recipient.from_jwk(data)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)


class TestRecipients:
    """
    Tests for Recipients.
    """

    def test_recipients_constructor(self):
        r = Recipients([RecipientInterface()])
        assert isinstance(r, Recipients)

    def test_recipients_constructor_with_recipient_alg_direct(self):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="our-secret")
        r = Recipients([Recipient.new(unprotected={1: -6, 4: b"our-secret"})])
        key = r.extract([key])
        assert key.kty == 4
        assert key.alg == 4
        assert key.kid == b"our-secret"

    def test_recipients_extract_without_key(self):
        r = Recipients([RecipientInterface(unprotected={1: -6, 4: b"our-secret"})])
        with pytest.raises(ValueError) as err:
            r.extract([])
            pytest.fail("extract() should fail.")
        assert "key is not found." in str(err.value)

    def test_recipients_extract_without_context(self, material):
        r = Recipients(
            [
                Recipient.new(
                    unprotected={"alg": "direct+HKDF-SHA-256", "kid": "02"},
                )
            ],
            True,
        )
        with pytest.raises(ValueError) as err:
            r.extract(keys=[material])
            pytest.fail("extract() should fail.")
        assert "context should be set." in str(err.value)

    def test_recipients_extract_with_empty_recipients(self, material, context):
        r = Recipients([])
        with pytest.raises(ValueError) as err:
            r.extract(context=context, keys=[material])
            pytest.fail("extract() should fail.")
        assert "No recipients." in str(err.value)

    def test_recipients_extract_with_multiple_materials(self, material, context):
        r1 = Recipient.from_jwk(
            {
                "alg": "direct",
                "kid": "01",
            }
        )
        r2 = Recipient.from_jwk(
            {
                "alg": "direct+HKDF-SHA-256",
                "kid": "02",
                "salt": "aabbccddeeffgghh",
            }
        )
        rs = Recipients([r1, r2])
        key = rs.extract(context=context, keys=[material])
        assert key.alg == 10
        assert key.kid == b"02"

    def test_recipients_extract_with_multiple_keys(self, material):
        mac_key = COSEKey.from_symmetric_key(
            bytes.fromhex(
                "DDDC08972DF9BE62855291A17A1B4CF767C2DC762CB551911893BF7754988B0A286127BFF5D60C4CBC877CAC4BF3BA02C07AD544C951C3CA2FC46B70219BC3DC"
            ),
            alg="HS512",
        )
        r1 = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
            }
        )
        r2 = Recipient.from_jwk(
            {
                "alg": "direct+HKDF-SHA-256",
                "kid": "02",
                "salt": "aabbccddeeffgghh",
            },
        )
        r3 = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "03",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        k3 = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "03",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        r3.apply(mac_key)
        rs = Recipients([r1, r2, r3])
        key = rs.extract(keys=[k3], alg=7)
        assert key.alg == 7
        assert key.kid == b"03"

    def test_recipients_extract_with_different_kid(self):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="our-secret")
        r = Recipients([RecipientInterface(unprotected={1: -6, 4: b"your-secret"})])
        with pytest.raises(ValueError) as err:
            r.extract([key])
            pytest.fail("extract() should fail.")
        assert "key is not found." in str(err.value)

    def test_recipients_from_list(self):
        try:
            Recipients.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b""]])
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_from_list_with_empty_recipients(self):
        try:
            Recipients.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b"", []]])
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_from_list_with_recipients(self):
        try:
            Recipients.from_list(
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
    def test_recipients_from_list_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            Recipients.from_list(invalid)
            pytest.fail("extract() should fail.")
        assert msg in str(err.value)
