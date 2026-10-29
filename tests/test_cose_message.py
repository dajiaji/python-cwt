# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEMessage.
"""

import copy
from types import MappingProxyType

import cbor2
import pytest

from cwt import COSE, COSEKey, COSEMessage, COSETypes, Recipient, Signer, VerifyError
from cwt.enums import COSEAlgs, COSEHeaders

from .utils import key_path


@pytest.fixture(scope="session")
def signing_key():
    with open(key_path("private_key_ed25519.json")) as key_file:
        return COSEKey.from_jwk(key_file.read())


class TestCOSEMessage:
    """
    Tests for COSEMessage.
    """

    def test_cose_message_constructor_with_mac0(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)
        sig = COSEMessage.loads(encoded)
        assert sig.type == COSETypes.MAC0
        assert sig.payload == b"Hello world!"
        assert sig.signatures == []
        assert sig.recipients == []
        assert len(sig.other_fields) == 1

    def test_cose_message_mac0_countersignature(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)
        try:
            sig = COSEMessage.loads(countersigned).counterverify(pub_key)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.EDDSA  # alg: "EdDSA"
        assert countersignature.unprotected[COSEHeaders.KID] == b"01"  # kid: b"01"

    def test_cose_message_mac0_countersignature_with_abbreviated(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary, abbreviated=True).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)
        try:
            if COSEMessage.loads(countersigned).counterverify(pub_key) is not None:
                pytest.fail("counterverify should return None.")
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")

    def test_cose_message_mac0_countersignature_with_multiple_signers(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary-1 side:
        notary1 = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned1 = COSEMessage.loads(encoded).countersign(notary1).dumps()

        # The notary-2 side:
        notary2 = Signer.from_jwk(
            {
                "kid": "02",
                "kty": "EC",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
                "d": "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
            },
        )
        countersigned2 = COSEMessage.loads(countersigned1).countersign(notary2).dumps()

        # The recipient side:
        pub_key1 = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        pub_key2 = COSEKey.from_jwk(
            {
                "kid": "02",
                "kty": "EC",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned2, mac_key)

        try:
            sig = COSEMessage.loads(countersigned2).counterverify(pub_key1)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.EDDSA  # alg: "EdDSA"
        assert countersignature.unprotected[COSEHeaders.KID] == b"01"  # kid: b"01"

        try:
            sig = COSEMessage.loads(countersigned2).counterverify(pub_key2)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.ES256  # alg: "ES256"
        assert countersignature.unprotected[COSEHeaders.KID] == b"02"  # kid: b"02"

    def test_cose_message_mac0_countersignature_without_kid(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                # "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                # "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)
        try:
            sig = COSEMessage.loads(countersigned).counterverify(pub_key)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.EDDSA  # alg: "EdDSA"

    def test_cose_message_mac0_countersignature_without_different_kid(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "02",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(countersigned).counterverify(pub_key)
            pytest.fail("counterverify() should fail.")
        assert "kid mismatch." in str(err.value)

    def test_cose_usage_examples_cose_mac_countersignature(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        r = Recipient.new(unprotected={"alg": "direct", "kid": mac_key.kid})
        sender = COSE.new()
        encoded = sender.encode(b"Hello world!", mac_key, protected={"alg": "HS256"}, recipients=[r])

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        msg = COSEMessage.loads(encoded)
        COSEMessage.from_cose_recipient(msg.recipients[0]).countersign(notary)
        countersigned = msg.dumps()

        # print(countersigned.hex())

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)
        try:
            msg = COSEMessage.loads(countersigned)
            sig = COSEMessage.from_cose_recipient(msg.recipients[0]).counterverify(pub_key)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.EDDSA  # alg: "EdDSA"
        assert countersignature.unprotected[COSEHeaders.KID] == b"01"  # kid: b"01"

    @pytest.mark.parametrize(
        "type, msg, err_msg",
        [
            (COSETypes.MAC0, [], "Invalid COSE message."),
            (COSETypes.MAC0, [{}, {}, b""], "The protected headers should be bytes."),
            (COSETypes.MAC0, [b"", b"", b""], "The unprotected headers should be Dict[int, Any]."),
            (COSETypes.MAC0, [b"", {COSEHeaders.COUNTER_SIGNATURE_V2: {}}, b""], "The countersignature should be array."),
            (COSETypes.MAC0, [b"", {COSEHeaders.COUNTER_SIGNATURE_V2: []}, b""], "Invalid countersignature."),
            (COSETypes.MAC0, [b"", {COSEHeaders.COUNTER_SIGNATURE_V2: [b""]}, b""], "Invalid COSE message."),
            (COSETypes.MAC0, [b"", {COSEHeaders.COUNTER_SIGNATURE_V2: [""]}, b""], "Invalid countersignature."),
            (COSETypes.MAC0, [b"", {}, b""], "Invalid COSE_Mac0 message."),
            (COSETypes.MAC0, [b"", {}, b"", {}], "tag should be bytes."),
            (COSETypes.ENCRYPT0, [b"", {}, b"", {}], "Invalid COSE_Encrypt0 message."),
            (COSETypes.ENCRYPT, [b"", {}, b""], "Invalid COSE_Encrypt message."),
            (COSETypes.ENCRYPT, [b"", {}, b"", {}], "The COSE recipients should be array."),
            (COSETypes.MAC, [b"", {}, b"", {}], "Invalid COSE_Mac message."),
            (COSETypes.MAC, [b"", {}, b"", {}, {}], "The tag value should be bytes."),
            (COSETypes.MAC, [b"", {}, b"", b"", {}], "The COSE recipients should be array."),
            (COSETypes.MAC, [b"", {}, b"", b"", [[]]], "Invalid COSE message."),
            (COSETypes.SIGN1, [b"", {}, b""], "Invalid COSE_Sign1 message."),
            (COSETypes.SIGN1, [b"", {}, b"", {}], "The COSE signature should be bytes."),
            (COSETypes.SIGN, [b"", {}, b""], "Invalid COSE_Sign message."),
            (COSETypes.SIGN, [b"", {}, b"", {}], "The COSE signatures should be array."),
            (COSETypes.SIGN, [b"", {}, b"", [[]]], "Invalid COSE message."),
            (COSETypes.COUNTERSIGNATURE, [b"", {}, b"", {}], "Invalid COSE_Countersignature."),
            (COSETypes.SIGNATURE, [b"", {}, b"", {}], "Invalid COSE_Signature."),
            (COSETypes.RECIPIENT, [b"", {}, b"", {}], "Invalid COSE_Recipient."),
            (-1, [b"", {}, b""], "Invalid COSETypes(-1) for COSE message."),
        ],
    )
    def test_cose_message_constructor_with_invalid_args(self, type, msg, err_msg):
        with pytest.raises(ValueError) as err:
            COSEMessage(type, msg)
            pytest.fail("COSEMessage() should not fail.")
        assert err_msg in str(err.value)

    def test_cose_message_loads_with_empty_bytes(self):
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(cbor2.dumps(b"xxx"))
            pytest.fail("loads() should not fail.")
        assert "Invalid COSE format." in str(err.value)

    def test_cose_message_loads_with_invalid_tags(self):
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(9999, b"xxx")))
            pytest.fail("loads() should not fail.")
        assert "Unknown CBOR tag for COSE message: 9999." in str(err.value)

    def test_cose_message_counterverify_without_countersign(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        # notary = Signer.from_jwk(
        #     {
        #         "kid": "01",
        #         "kty": "OKP",
        #         "crv": "Ed25519",
        #         "alg": "EdDSA",
        #         "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        #         "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
        #     },
        # )
        # countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, mac_key)
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(encoded).counterverify(pub_key)
            pytest.fail("counterverify() should not fail.")
        assert "Countersignature not found." in str(err.value)

    def test_cose_message_counterverify_with_different_countersignature(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "EC",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)

        with pytest.raises(VerifyError) as err:
            COSEMessage.loads(countersigned).counterverify(pub_key)
            pytest.fail("counterverify() should not fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_message_counterverify_with_different_abbreviated_countersignature(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        countersigned = COSEMessage.loads(encoded).countersign(notary, abbreviated=True).dumps()

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "EC",
                "crv": "P-256",
                "x": "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
                "y": "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key)

        with pytest.raises(VerifyError) as err:
            COSEMessage.loads(countersigned).counterverify(pub_key)
            pytest.fail("counterverify() should not fail.")
        assert "Failed to verify." in str(err.value)

    def test_cose_message_detach_payload(self):
        """
        Detach the payload from a COSE message.
        For example, [an example message](https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-sig-01.json)
        ```
        18([
          / protected: / h'A201260300',
          / unprotected: / {4: h'3131'},
          / payload: / h'546869732069732074686520636F6E74656E742E',
          / signature: / h'6520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B'
        ])
        ```
        would be separated into
        ```
        18([
          / protected: / h'A201260300',
          / unprotected: / {4: h'3131'},
          / payload: / null / detached /,
          / signature: / h'6520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B'
        ])
        ```
        and
        ```
        546869732069732074686520636F6E74656E742E
        ```

        """
        ecdsa_cose_sign1_example = COSEMessage.loads(
            bytes.fromhex(
                "D28445A201260300A10442313154546869732069732074686520636F6E74656E742E58406520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B"
            )
        )
        expected_detached_cose_message = COSEMessage.loads(
            bytes.fromhex(
                "D28445A201260300A104423131F658406520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B"
            )
        )
        expected_payload = bytes.fromhex("546869732069732074686520636F6E74656E742E")

        detached_content_cose_message, detached_payload = ecdsa_cose_sign1_example.detach_payload()
        assert expected_detached_cose_message == detached_content_cose_message
        assert expected_detached_cose_message.dumps() == detached_content_cose_message.dumps()
        assert expected_payload == detached_payload

        data = cbor2.loads(detached_content_cose_message.dumps())
        assert data.value[2] is None
        value = list(data.value)
        value[2] = detached_payload
        reverted_cose_message = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(data.tag, value)))
        assert reverted_cose_message.payload == expected_payload

        reverted_cose_message = detached_content_cose_message.attach_payload(detached_payload)
        assert ecdsa_cose_sign1_example == reverted_cose_message

    def test_cose_message_detach_payload_with_mac0(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)
        msg = COSEMessage.loads(encoded)
        with pytest.raises(ValueError) as err:
            msg.attach_payload(b"Hello world!")
            pytest.fail("attach_payload() should fail.")
        assert "The payload already exists." in str(err.value)

        detached, payload = msg.detach_payload()
        assert payload == b"Hello world!"
        assert msg.payload is None
        with pytest.raises(ValueError) as err:
            detached.detach_payload()
            pytest.fail("detach_payload() should fail.")
        assert "The payload does not exist." in str(err.value)

        recipient = COSE.new()

        assert b"Hello world!" == recipient.decode(detached.dumps(), mac_key, detached_payload=payload)

        with pytest.raises(ValueError) as err:
            recipient.decode(detached.dumps(), mac_key)
            pytest.fail("decode() should fail.")
        assert "detached_payload should be set." in str(err.value)

        with pytest.raises(ValueError) as err:
            recipient.decode(encoded, mac_key, detached_payload=payload)
            pytest.fail("decode() should fail.")
        assert "The payload already exists." in str(err.value)

    def test_cose_message_detach_payload_with_mac0_countersignature(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode(b"Hello world!", mac_key)

        # The notary side:
        notary = Signer.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            },
        )
        detached, payload = COSEMessage.loads(encoded).detach_payload()
        countersigned = COSEMessage.loads(detached.dumps()).countersign(notary, detached_payload=payload).dumps()
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(encoded).countersign(notary, detached_payload=payload)
            pytest.fail("countersign() should fail.")
        assert "The payload already exists." in str(err.value)

        countersigned2 = COSEMessage.loads(encoded).countersign(notary).dumps()
        with pytest.raises(ValueError) as err:
            COSEMessage.loads(countersigned2).counterverify(notary, detached_payload=payload)
            pytest.fail("counterverify() should fail.")
        assert "The payload already exists." in str(err.value)

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kid": "01",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            },
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(countersigned, mac_key, detached_payload=payload)
        try:
            sig = COSEMessage.loads(countersigned).counterverify(pub_key, detached_payload=payload)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")

        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[COSEHeaders.ALG] == COSEAlgs.EDDSA  # alg: "EdDSA"
        assert countersignature.unprotected[COSEHeaders.KID] == b"01"  # kid: b"01"

    @pytest.mark.parametrize(
        "tag, fields",
        [
            (16, [b"", {}, b"payload"]),
            (96, [b"", {}, b"payload", [[b"", {}, b""]]]),
            (17, [b"", {}, b"payload", b"mac"]),
            (97, [b"", {}, b"payload", b"mac", [[b"", {}, b""]]]),
            (18, [b"", {}, b"payload", b"signature"]),
            (98, [b"", {}, b"payload", [[b"", {}, b"signature"]]]),
        ],
    )
    def test_cose_message_loads_with_immutable_headers(self, tag, fields):
        fields[1][1000] = {"chain": [b"certificate"]}
        encoded = cbor2.dumps(cbor2.CBORTag(tag, fields))

        message = COSEMessage.loads(encoded)

        assert isinstance(message.unprotected, dict)
        assert isinstance(message.unprotected[1000], dict)
        assert isinstance(message.unprotected[1000]["chain"], list)

    @pytest.mark.parametrize("tag", [96, 97])
    def test_cose_message_loads_with_nested_immutable_recipients(self, tag):
        recipient = [
            b"",
            {COSEHeaders.ALG: COSEAlgs.A128KW, COSEHeaders.KID: b"parent"},
            b"wrapped key",
            [[b"", {COSEHeaders.ALG: COSEAlgs.DIRECT, COSEHeaders.KID: b"child"}, b""]],
        ]
        if tag == 96:
            fields = [b"", {}, b"payload", [recipient]]
        else:
            fields = [b"", {}, b"payload", b"mac", [recipient]]

        message = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(tag, fields)))

        assert message.recipients == [recipient]
        assert isinstance(message.recipients, list)
        assert isinstance(message.recipients[0], list)
        assert isinstance(message.recipients[0][1], dict)
        assert isinstance(message.recipients[0][3][0], list)
        assert isinstance(message.recipients[0][3][0][1], dict)

    def test_cose_message_loads_with_immutable_signatures(self):
        fields = [b"", {}, b"payload", [[b"", {COSEHeaders.KID: b"signer"}, b"signature"]]]

        message = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(98, fields)))

        assert isinstance(message.signatures, list)
        assert isinstance(message.signatures[0], list)
        assert isinstance(message.signatures[0][1], dict)
        assert message.signatures[0][1][COSEHeaders.KID] == b"signer"

    @pytest.mark.parametrize("tag", [18, 98])
    def test_cose_message_dumps_preserves_protected_header_bytes(self, tag):
        protected = bytes.fromhex("a1180127")
        if tag == 18:
            fields = [protected, {}, b"payload", b"signature"]
        else:
            fields = [protected, {}, b"payload", [[protected, {}, b"signature"]]]
        encoded = cbor2.dumps(cbor2.CBORTag(tag, fields))

        assert COSEMessage.loads(encoded).dumps() == encoded

    def test_cose_message_constructor_with_mapping_and_tuple(self):
        headers = MappingProxyType({1000: MappingProxyType({(1, 2): (b"value",)})})
        fields = (b"", headers, b"payload", b"signature")

        message = COSEMessage(COSETypes.SIGN1, fields)

        assert message.unprotected[1000][(1, 2)] == [b"value"]
        message.unprotected[1000][(1, 2)].append(b"another")
        assert headers[1000][(1, 2)] == (b"value",)

    def test_cose_message_constructor_preserves_mutable_input_references(self):
        headers = {1000: (b"metadata",)}
        fields = [b"", headers, b"payload", b"signature"]

        message = COSEMessage(COSETypes.SIGN1, fields)
        message.detach_payload()

        assert message.unprotected is headers
        assert headers[1000] == [b"metadata"]
        assert fields[2] is None

    @pytest.mark.parametrize(
        "type, fields",
        [
            (COSETypes.ENCRYPT, (b"", {}, b"payload", ())),
            (COSETypes.MAC, (b"", {}, b"payload", b"mac", ())),
            (COSETypes.SIGN, (b"", {}, b"payload", ())),
        ],
    )
    def test_cose_message_constructor_with_empty_immutable_children(self, type, fields):
        message = COSEMessage(type, fields)

        assert isinstance(message.recipients, list)
        assert isinstance(message.signatures, list)
        assert message.recipients == []
        assert message.signatures == []

    def test_cose_message_loads_preserves_shared_containers(self):
        shared = [b"leaf"]
        for _ in range(12):
            shared = [shared, shared]
        fields = [b"", {1000: shared, 1001: shared}, b"payload", b"signature"]
        encoded = cbor2.dumps(cbor2.CBORTag(18, fields), value_sharing=True)

        message = COSEMessage.loads(encoded)

        assert len(encoded) < 512
        assert message.unprotected[1000] is message.unprotected[1001]
        node = message.unprotected[1000]
        for _ in range(12):
            assert isinstance(node, list)
            assert node[0] is node[1]
            node = node[0]
        assert node == [b"leaf"]

    def test_cose_message_shared_mutable_containers_are_visited_once(self):
        visits = []

        class CountedList(list):
            def __iter__(self):
                visits.append(self)
                return super().__iter__()

        shared = CountedList([b"leaf"])
        for _ in range(12):
            shared = CountedList([shared, shared])

        message = COSEMessage(COSETypes.SIGN1, [b"", {1000: shared, 1001: shared}, b"payload", b"signature"])

        assert len(visits) == 13
        assert message.unprotected[1000] is shared
        assert message.unprotected[1001] is shared

    def test_cose_message_countersign_loaded_message(self, signing_key):
        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = cose.encode(b"payload", signing_key)
        signer = Signer.new(signing_key, {COSEHeaders.ALG: signing_key.alg}, {COSEHeaders.KID: signing_key.kid})

        countersigned = COSEMessage.loads(encoded).countersign(signer).dumps()
        signature = COSEMessage.loads(countersigned).counterverify(signing_key)

        assert isinstance(signature, list)
        assert isinstance(signature[1], dict)
        assert cose.decode(countersigned, signing_key) == b"payload"

    def test_cose_message_countersign_loaded_message_abbreviated(self, signing_key):
        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = cose.encode(b"payload", signing_key)
        signer = Signer.new(signing_key, {COSEHeaders.ALG: signing_key.alg}, {COSEHeaders.KID: signing_key.kid})

        countersigned = COSEMessage.loads(encoded).countersign(signer, abbreviated=True).dumps()

        assert COSEMessage.loads(countersigned).counterverify(signing_key) is None
        assert cose.decode(countersigned, signing_key) == b"payload"

    def test_cose_message_countersign_loaded_message_multiple_times(self, signing_key):
        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = cose.encode(b"payload", signing_key)
        signer = Signer.new(signing_key, {COSEHeaders.ALG: signing_key.alg}, {COSEHeaders.KID: signing_key.kid})

        for _ in range(3):
            encoded = COSEMessage.loads(encoded).countersign(signer).dumps()
        message = COSEMessage.loads(encoded)

        assert len(message.unprotected[COSEHeaders.COUNTER_SIGNATURE_V2]) == 3
        assert isinstance(message.counterverify(signing_key), list)
        assert cose.decode(encoded, signing_key) == b"payload"

    @pytest.mark.parametrize("tag", [96, 97])
    def test_cose_message_countersign_recipient_updates_parent(self, tag, signing_key):
        recipient = [b"", {}, b"child payload"]
        if tag == 96:
            fields = [b"", {}, b"payload", [recipient]]
        else:
            fields = [b"", {}, b"payload", b"mac", [recipient]]
        message = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(tag, fields)))
        signer = Signer.new(signing_key, {COSEHeaders.ALG: signing_key.alg}, {COSEHeaders.KID: signing_key.kid})

        COSEMessage.from_cose_recipient(message.recipients[0]).countersign(signer)

        assert COSEHeaders.COUNTER_SIGNATURE_V2 in message.recipients[0][1]
        loaded = COSEMessage.loads(message.dumps())
        assert isinstance(COSEMessage.from_cose_recipient(loaded.recipients[0]).counterverify(signing_key), list)

    def test_cose_message_countersign_signature_updates_parent(self, signing_key):
        fields = [b"", {}, b"payload", [[b"", {}, b"signature"]]]
        message = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(98, fields)))
        signer = Signer.new(signing_key, {COSEHeaders.ALG: signing_key.alg}, {COSEHeaders.KID: signing_key.kid})

        COSEMessage.from_cose_signature(message.signatures[0]).countersign(signer)

        assert COSEHeaders.COUNTER_SIGNATURE_V2 in message.signatures[0][1]
        loaded = COSEMessage.loads(message.dumps())
        assert isinstance(COSEMessage.from_cose_signature(loaded.signatures[0]).counterverify(signing_key), list)

    @pytest.mark.parametrize("headers", [b"", "", [], (), None, 42])
    def test_cose_message_loads_with_non_map_unprotected_headers(self, headers):
        encoded = cbor2.dumps(cbor2.CBORTag(18, (b"", headers, b"payload", b"signature")))

        with pytest.raises(ValueError, match="unprotected header"):
            COSEMessage.loads(encoded)

    @pytest.mark.parametrize("value", [b"abc", "abc", {}, None, 42])
    def test_cose_message_from_cose_signature_with_non_array(self, value):
        with pytest.raises(ValueError, match="COSE message"):
            COSEMessage.from_cose_signature(value)

    @pytest.mark.parametrize("value", [b"abc", "abc", {}, 42])
    def test_cose_message_constructor_with_non_array_countersignatures(self, value):
        fields = (b"", {COSEHeaders.COUNTER_SIGNATURE_V2: value}, b"payload", b"signature")

        with pytest.raises(ValueError, match="countersignature"):
            COSEMessage(COSETypes.SIGN1, fields)

    @pytest.mark.parametrize(
        "type, fields, err_msg",
        [
            (COSETypes.SIGN1, [123, {}, b"payload", b"signature"], "protected headers"),
            (COSETypes.SIGN1, [b"", {}, 123, b"signature"], "payload"),
            (COSETypes.ENCRYPT0, [b"", {}, b"payload", b"extra"], "Invalid COSE_Encrypt0"),
            (COSETypes.ENCRYPT, [b"", {}, b"payload"], "Invalid COSE_Encrypt"),
            (COSETypes.MAC0, [b"", {}, b"payload"], "Invalid COSE_Mac0"),
            (COSETypes.MAC, [b"", {}, b"payload"], "Invalid COSE_Mac"),
            (COSETypes.SIGN1, [b"", {}, b"payload"], "Invalid COSE_Sign1"),
            (COSETypes.SIGN, [b"", {}, b"payload"], "Invalid COSE_Sign"),
            (COSETypes.RECIPIENT, [b"", {}, b"payload", b"extra"], "Invalid COSE_Recipient"),
            (COSETypes.SIGNATURE, [b"", {}, b"payload", b"extra"], "Invalid COSE_Signature"),
            (COSETypes.COUNTERSIGNATURE, [b"", {}, b"payload", b"extra"], "Invalid COSE_Countersignature"),
            (COSETypes.MAC0, [b"", {}, b"payload", 123], "tag should be bytes"),
            (COSETypes.MAC, [b"", {}, b"payload", 123, []], "tag value should be bytes"),
            (COSETypes.SIGN1, [b"", {}, b"payload", 123], "signature should be bytes"),
            (COSETypes.ENCRYPT, [b"", {}, b"payload", 123], "recipients should be array"),
            (COSETypes.MAC, [b"", {}, b"payload", b"mac", 123], "recipients should be array"),
            (COSETypes.SIGN, [b"", {}, b"payload", 123], "signatures should be array"),
            (COSETypes.ENCRYPT, [b"", {}, b"payload", [[123, {}, b"child"]]], "protected headers"),
            (COSETypes.SIGN, [b"", {}, b"payload", [[123, {}, b"signature"]]], "protected headers"),
            (-1, [b"", {}, b"payload"], "Invalid COSETypes"),
        ],
    )
    def test_cose_message_constructor_invalid_args_preserve_input(self, type, fields, err_msg):
        fields[1][1000] = (b"metadata",)
        original = copy.deepcopy(fields)

        with pytest.raises(ValueError, match=err_msg):
            COSEMessage(type, fields)

        assert fields == original

    def test_cose_message_invalid_countersignature_preserves_input(self):
        fields = [
            b"",
            {1000: (b"metadata",), COSEHeaders.COUNTER_SIGNATURE_V2: [123, {}, b"signature"]},
            b"payload",
            b"signature",
        ]
        original = copy.deepcopy(fields)

        with pytest.raises(ValueError, match="Invalid countersignature"):
            COSEMessage(COSETypes.SIGN1, fields)

        assert fields == original
