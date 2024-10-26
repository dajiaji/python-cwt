# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for Recipient.
"""
import cbor2
import pytest

from cwt import COSE, COSEKey, Recipient
from cwt.exceptions import DecodeError
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


@pytest.fixture(scope="session", autouse=True)
def rpk1():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "01",
            "crv": "P-256",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        }
    )


@pytest.fixture(scope="session", autouse=True)
def rpk2():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "02",
            "crv": "P-256",
            "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
            "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        }
    )


@pytest.fixture(scope="session", autouse=True)
def rsk1():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "01",
            "crv": "P-256",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
        }
    )


@pytest.fixture(scope="session", autouse=True)
def rsk2():
    return COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "02",
            "crv": "P-256",
            "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
            "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
        }
    )


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
            r.encode(b"")
            pytest.fail("encode() should fail.")
        with pytest.raises(NotImplementedError):
            r.decode(k)
            pytest.fail("decode() should fail.")
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
                {1: -6},
                {1: -6},
                "alg appear both in protected and unprotected.",
            ),
            (
                {1: -65535},
                {},
                # "Unsupported or unknown alg(1): -65535.",
                "context should be set.",
            ),
        ],
    )
    def test_recipient_new_with_invalid_arg(self, protected, unprotected, msg):
        with pytest.raises(ValueError) as err:
            Recipient.new(protected, unprotected)
            pytest.fail("Recipient() should fail.")
        assert msg in str(err.value)

    def test_recipient_from_jwk_with_str(self):
        recipient = Recipient.new(unprotected={"alg": "direct"})
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -6

    def test_recipient_from_jwk_with_dict(self):
        k = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "key_ops": ["wrapKey"]})
        recipient = Recipient.new(unprotected={"alg": "A128KW"}, sender_key=k)
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -3

    def test_recipient_from_jwk_with_dict_and_with_byte_formatted_kid(self):
        k = COSEKey.from_jwk({"kty": "oct", "kid": b"01", "alg": "A128KW", "key_ops": ["wrapKey"]})
        recipient = Recipient.new(unprotected={"kid": b"01", "alg": "A128KW"}, sender_key=k)
        assert isinstance(recipient, RecipientInterface)
        assert recipient.alg == -3
        assert recipient.kid == b"01"

    # def test_recipient_from_jwk_with_context(self):
    #     recipient = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "direct+HKDF-SHA-256",
    #             "context": {
    #                 "apu": {
    #                     "id": "sender-01",
    #                     "nonce": "xxx",
    #                     "other": "yyy",
    #                 },
    #                 "apv": {
    #                     "id": "recipient-01",
    #                     "nonce": "abc",
    #                     "other": "def",
    #                 },
    #             },
    #         }
    #     )
    #     assert isinstance(recipient, RecipientInterface)
    #     assert recipient.alg == -10
    #     assert recipient._unprotected[-21] == b"sender-01"
    #     assert recipient._unprotected[-22] == b"xxx"
    #     assert recipient._unprotected[-23] == b"yyy"
    #     assert recipient._unprotected[-24] == b"recipient-01"
    #     assert recipient._unprotected[-25] == b"abc"
    #     assert recipient._unprotected[-26] == b"def"

    # def test_recipient_from_jwk_with_context_id(self):
    #     recipient = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "direct+HKDF-SHA-256",
    #             "context": {
    #                 "apu": {
    #                     "id": "sender-01",
    #                 },
    #                 "apv": {
    #                     "id": "recipient-01",
    #                 },
    #             },
    #         }
    #     )
    #     assert isinstance(recipient, RecipientInterface)
    #     assert recipient.alg == -10
    #     assert recipient._unprotected[-21] == b"sender-01"
    #     assert -22 not in recipient._unprotected
    #     assert -23 not in recipient._unprotected
    #     assert recipient._unprotected[-24] == b"recipient-01"
    #     assert -25 not in recipient._unprotected
    #     assert -26 not in recipient._unprotected

    # def test_recipient_from_jwk_with_context_nonce(self):
    #     recipient = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "direct+HKDF-SHA-256",
    #             "context": {
    #                 "apu": {
    #                     "nonce": "xxx",
    #                 },
    #                 "apv": {
    #                     "nonce": "abc",
    #                 },
    #             },
    #         }
    #     )
    #     assert isinstance(recipient, RecipientInterface)
    #     assert recipient.alg == -10
    #     assert -21 not in recipient._unprotected
    #     assert recipient._unprotected[-22] == b"xxx"
    #     assert -23 not in recipient._unprotected
    #     assert -24 not in recipient._unprotected
    #     assert recipient._unprotected[-25] == b"abc"
    #     assert -26 not in recipient._unprotected

    # def test_recipient_from_jwk_with_context_other(self):
    #     recipient = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "direct+HKDF-SHA-256",
    #             "context": {
    #                 "apu": {
    #                     "other": "yyy",
    #                 },
    #                 "apv": {
    #                     "other": "def",
    #                 },
    #             },
    #         }
    #     )
    #     assert isinstance(recipient, RecipientInterface)
    #     assert recipient.alg == -10
    #     assert -21 not in recipient._unprotected
    #     assert -22 not in recipient._unprotected
    #     assert recipient._unprotected[-23] == b"yyy"
    #     assert -24 not in recipient._unprotected
    #     assert -25 not in recipient._unprotected
    #     assert recipient._unprotected[-26] == b"def"

    @pytest.mark.parametrize(
        "data, key, msg",
        [
            (
                {"foo": "bar"},
                {"kty": "oct", "foo": "bar"},
                "alg(3) not found.",
            ),
            (
                {"alg": "xxx"},
                {"kty": "oct", "alg": "xxx"},
                "Unsupported or unknown alg: xxx.",
            ),
            (
                {"alg": 123},
                {"kty": "oct", "alg": 123},
                "alg should be str.",
            ),
            (
                {"alg": "direct", "kid": 123},
                {"kty": "oct", "alg": "direct", "kid": 123},
                "kid should be str or bytes.",
            ),
            (
                {"alg": "A128KW", "kid": 123},
                {"kty": "oct", "alg": "A128KW", "kid": 123},
                "kid should be str or bytes.",
            ),
            (
                {"alg": "A128KW", "salt": 123},
                {"kty": "oct", "alg": "A128KW"},
                "salt should be bytes or str.",
            ),
            (
                {"alg": "A128KW"},
                {"kty": "oct", "alg": "A128KW", "key_ops": 123},
                "key_ops should be list.",
            ),
            (
                {"alg": "A128KW"},
                {"kty": "oct", "alg": "A128KW", "key_ops": [123]},
                "Unsupported or unknown key_ops.",
            ),
            (
                {"alg": "A128KW"},
                {"kty": "oct", "alg": "A128KW", "key_ops": ["xxx"]},
                "Unsupported or unknown key_ops.",
            ),
            (
                {"alg": "A128KW"},
                {"kty": "oct", "alg": "A128KW", "k": 123},
                "k should be str.",
            ),
            (
                {"alg": "direct+HKDF-SHA-256", "context": []},
                {"kty": "oct", "alg": "direct+HKDF-SHA-256"},
                "Unsupported or unknown alg(3): -10.",
            ),
        ],
    )
    def test_recipient_from_jwk_with_invalid_arg(self, data, key, msg):
        with pytest.raises(ValueError) as err:
            Recipient.new(unprotected=data, sender_key=COSEKey.from_jwk(key))
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
        key = r.derive_key([key], key.alg, b"", b"")
        assert key.kty == 4
        assert key.alg == 4
        assert key.kid == b"our-secret"

    def test_recipients_derive_key_without_key(self):
        r = Recipients([RecipientInterface(unprotected={1: -6, 4: b"our-secret"})])
        with pytest.raises(ValueError) as err:
            r.derive_key([], 0, b"", b"")
            pytest.fail("derive_key() should fail.")
        assert "key is not found." in str(err.value)

    # def test_recipients_derive_key_without_context(self, material):
    #     r = Recipients(
    #         [
    #             Recipient.new(
    #                 unprotected={"alg": "direct+HKDF-SHA-256", "kid": "02"},
    #             )
    #         ],
    #         True,
    #     )
    #     with pytest.raises(ValueError) as err:
    #         r.derive_key(keys=[material])
    #         pytest.fail("derive_key() should fail.")
    #     assert "context should be set." in str(err.value)

    def test_recipients_derive_key_with_empty_recipients(self, material, context):
        r = Recipients([])
        with pytest.raises(ValueError) as err:
            r.derive_key([material], 0, b"", b"")
            pytest.fail("derive_key() should fail.")
        assert "No recipients." in str(err.value)

    # def test_recipients_derive_key_with_multiple_materials(self, material, context):
    #     r1 = Recipient.from_jwk(
    #         {
    #             "alg": "direct",
    #             "kid": "01",
    #         }
    #     )
    #     r2 = Recipient.from_jwk(
    #         {
    #             "alg": "direct+HKDF-SHA-256",
    #             "kid": "02",
    #             "salt": "aabbccddeeffgghh",
    #         }
    #     )
    #     rs = Recipients([r1, r2])
    #     key = rs.derive_key(context=context, keys=[material])
    #     assert key.alg == 10
    #     assert key.kid == b"02"

    # def test_recipients_derive_key_with_multiple_keys(self, material):
    #     mac_key = COSEKey.from_symmetric_key(
    #         bytes.fromhex(
    #             "DDDC08972DF9BE62855291A17A1B4CF767C2DC762CB551911893BF7754988B0A286127BFF5D60C4CBC877CAC4BF3BA02C07AD544C951C3CA2FC46B70219BC3DC"
    #         ),
    #         alg="HS512",
    #     )
    #     r1 = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "A128KW",
    #             "kid": "01",
    #         }
    #     )
    #     r2 = Recipient.from_jwk(
    #         {
    #             "alg": "direct+HKDF-SHA-256",
    #             "kid": "02",
    #             "salt": "aabbccddeeffgghh",
    #         },
    #     )
    #     r3 = Recipient.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "A128KW",
    #             "kid": "03",
    #             "k": "hJtXIZ2uSN5kbQfbtTNWbg",
    #         },
    #     )
    #     k3 = COSEKey.from_jwk(
    #         {
    #             "kty": "oct",
    #             "alg": "A128KW",
    #             "kid": "03",
    #             "k": "hJtXIZ2uSN5kbQfbtTNWbg",
    #         },
    #     )
    #     rs = Recipients([r1, r2, r3])
    #     key = rs.derive_key(keys=[k3], alg=7)
    #     assert key.alg == 7
    #     assert key.kid == b"03"

    def test_recipients_derive_key_with_different_kid(self):
        key = COSEKey.from_symmetric_key("mysecret", alg="HMAC 256/64", kid="our-secret")
        r = Recipients([RecipientInterface(unprotected={1: -6, 4: b"your-secret"})])
        with pytest.raises(ValueError) as err:
            r.derive_key([key], key.alg, b"", b"")
            pytest.fail("derive_key() should fail.")
        assert "key is not found." in str(err.value)

    def test_recipients_from_list(self):
        try:
            Recipients.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b""]], context={"alg": "A128GCM"})
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_from_list_with_empty_recipients(self):
        try:
            Recipients.from_list([[cbor2.dumps({1: -10}), {-20: b"aabbccddeefff"}, b"", []]], context={"alg": "A128GCM"})
        except Exception:
            pytest.fail("from_list() should not fail.")

    def test_recipients_from_list_with_recipients(self):
        with pytest.raises(ValueError) as err:
            Recipients.from_list(
                [
                    [
                        cbor2.dumps({1: -10}),
                        {-20: b"aabbccddeefff"},
                        b"",
                        [[b"", {1: -6, 4: b"our-secret"}, b""]],
                    ]
                ],
                context={"alg": "A128GCM"},
            )
        assert "Recipients for direct encryption mode don't have recipients." in str(err.value)

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
            pytest.fail("from_list() should fail.")
        assert msg in str(err.value)

    def test_recipients_open_without_key(self):
        r = RecipientInterface(protected={1: -1}, unprotected={4: b"01", -4: [0x0010, 0x0001, 0x0001]})
        rs = Recipients([r])
        with pytest.raises(ValueError) as err:
            rs.derive_key([], 0, b"", b"")
            pytest.fail("open() should fail.")
        assert "key is not found." in str(err.value)

    def test_recipients_open_with_empty_recipients(self, rsk1):
        rs = Recipients([])
        with pytest.raises(ValueError) as err:
            rs.derive_key([rsk1], 0, b"", b"")
            pytest.fail("open() should fail.")
        assert "No recipients." in str(err.value)

    def test_recipients_open_with_rpk_without_kid(self, rsk1, rsk2):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        r = Recipient.new(protected={1: 35}, recipient_key=rpk)
        r.encode(enc_key.key)
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            enc_key,
            protected={
                1: 1,  # alg: "A128GCM"
            },
            recipients=[r],
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, [rsk1, rsk2])

    def test_recipients_open_with_verify_kid_and_rpk_without_kid(self, rsk1, rsk2):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        r = Recipient.new(protected={1: 35}, recipient_key=rpk)
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            enc_key,
            protected={"alg": "A128GCM"},
            recipients=[r],
        )
        recipient = COSE.new(verify_kid=True)
        with pytest.raises(ValueError) as err:
            recipient.decode(encoded, [rsk1])
            pytest.fail("decode() should fail.")
        assert "kid should be specified in recipient." in str(err.value)

    def test_recipients_open_failed_with_rpk_without_kid(self, rsk1):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        r = Recipient.new(protected={1: 35}, recipient_key=rpk)
        r.encode(enc_key.key)
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            enc_key,
            protected={"alg": "A128GCM"},
            recipients=[r],
        )
        recipient = COSE.new()
        with pytest.raises(DecodeError) as err:
            recipient.decode(encoded, [rsk1])
            pytest.fail("decode() should fail.")
        assert "Failed to open." in str(err.value)

    def test_recipients_open_with_multiple_rsks(self, rpk2, rsk1, rsk2):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        r = Recipient.new(protected={1: 35}, unprotected={4: b"02"}, recipient_key=rpk2)
        r.encode(enc_key.key)
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            key=enc_key,
            # protected={
            #     1: -1,  # alg: "HPKE"
            # },
            recipients=[r],
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, [rsk1, rsk2])

    def test_recipients_open_with_invalid_rsk(self, rpk1):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        r = Recipient.new(protected={1: 35}, unprotected={4: b"02"}, recipient_key=rpk1)
        # r.encode(enc_key.to_bytes())
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            enc_key,
            protected={"alg": "A128GCM"},
            recipients=[r],
        )
        invalid_rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
                "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
            }
        )
        recipient = COSE.new()
        with pytest.raises(DecodeError) as err:
            recipient.decode(encoded, [invalid_rsk])
            pytest.fail("decode() should fail.")
        assert "Failed to open." in str(err.value)

    @pytest.mark.parametrize(
        "kw_alg, enc_alg",
        [
            ("A128KW", "A128CTR"),
            ("A192KW", "A192CTR"),
            ("A256KW", "A256CTR"),
            ("A128KW", "A128CBC"),
            ("A192KW", "A192CBC"),
            ("A256KW", "A256CBC"),
        ],
    )
    def test_recipients_aes(self, kw_alg, enc_alg):
        kw_key = COSEKey.from_symmetric_key(alg=kw_alg)
        enc_key = COSEKey.from_symmetric_key(alg=enc_alg)

        # The sender side (must fail):
        r = Recipient.new(unprotected={"alg": kw_alg}, sender_key=kw_key)
        sender = COSE.new(alg_auto_inclusion=True)
        with pytest.raises(ValueError) as err:
            encoded = sender.encode_and_encrypt(
                b"Hello world!",
                enc_key,
                recipients=[r],
                enable_non_aead=False,
            )
            pytest.fail("encode_and_encrypt() should fail.")
        assert "Deprecated non-AEAD algorithm" in str(err.value)

        # The sender side (must fail):
        with pytest.raises(ValueError) as err:
            r = Recipient.new(protected={"alg": kw_alg}, sender_key=kw_key)
            pytest.fail("encode_and_encrypt() should fail.")
        assert "The protected header must be a zero-length string in key wrap mode with an AE algorithm." in str(err.value)

        # The sender side (must fail):
        r = Recipient.new(unprotected={"alg": kw_alg}, sender_key=kw_key)
        sender = COSE.new(alg_auto_inclusion=True)
        with pytest.raises(ValueError) as err:
            encoded = sender.encode_and_encrypt(
                b"Hello world!",
                enc_key,
                protected={"kid": "actually-not-protected"},
                recipients=[r],
                enable_non_aead=True,
            )
            pytest.fail("encode_and_encrypt() should fail.")
        assert "protected header MUST be zero-length" in str(err.value)

        # The sender side:
        r = Recipient.new(unprotected={"alg": kw_alg}, sender_key=kw_key)
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            recipients=[r],
            enable_non_aead=True,
        )

        # The recipient side (must fail):
        recipient = COSE.new()
        with pytest.raises(ValueError) as err:
            _ = recipient.decode(encoded, keys=[kw_key])  # the option enable_non_aead=False by default
            pytest.fail("decode() should fail for non-AEAD without enable_non_aead=True.")
        assert f"Deprecated non-AEAD algorithm: {enc_key._alg}." == str(err.value)

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, keys=[kw_key], enable_non_aead=True)

    @pytest.mark.parametrize(
        "enc_alg",
        [
            ("A128CTR"),
            ("A192CTR"),
            ("A256CTR"),
            ("A128CBC"),
            ("A192CBC"),
            ("A256CBC"),
        ],
    )
    def test_recipients_hpke(self, rsk1, rsk2, enc_alg):
        enc_key = COSEKey.from_symmetric_key(alg=enc_alg)
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        r = Recipient.new(unprotected={1: 35}, recipient_key=rpk)
        r.encode(enc_key.key)
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            enc_key,
            unprotected={"alg": enc_alg},
            recipients=[r],
            enable_non_aead=True,
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, [rsk1, rsk2], enable_non_aead=True)

    @pytest.mark.parametrize(
        "key_agreement_alg, key_agreement_alg_id, kw_alg, enc_alg",
        [
            ("ECDH-ES+A128KW", -29, "A128KW", "A128CTR"),
            ("ECDH-ES+A192KW", -30, "A192KW", "A192CTR"),
            ("ECDH-ES+A256KW", -31, "A256KW", "A256CTR"),
            ("ECDH-ES+A128KW", -29, "A128KW", "A128CBC"),
            ("ECDH-ES+A192KW", -30, "A192KW", "A192CBC"),
            ("ECDH-ES+A256KW", -31, "A256KW", "A256CBC"),
        ],
    )
    def test_recipients_ecdh_es(self, key_agreement_alg, key_agreement_alg_id, kw_alg, enc_alg):
        enc_key = COSEKey.from_symmetric_key(alg=enc_alg)
        context = {
            "alg": kw_alg,
            "supp_pub": {
                "key_data_length": len(enc_key.key) * 8,
                "protected": {},
            },
        }

        # The sender side:
        rsk1 = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                "alg": key_agreement_alg,
            }
        )
        rpk2 = COSEKey.from_jwk(
            {
                "kty": "EC",
                # "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            }
        )
        r = Recipient.new(unprotected={"alg": key_agreement_alg}, sender_key=rsk1, recipient_key=rpk2, context=context)

        nonce = enc_key.generate_nonce()
        sender = COSE.new()
        encoded = sender.encode(
            b"Hello world!",
            enc_key,
            protected={},
            unprotected={"alg": enc_alg, "iv": nonce},
            recipients=[r],
            enable_non_aead=True,
        )

        # The recipient side:
        rsk2 = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "02",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
                "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
                "alg": key_agreement_alg,
            }
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, rsk2, context, enable_non_aead=True)
