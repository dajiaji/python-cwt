# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEMessage.
"""

import cbor2
import pytest

from cwt import COSE, COSEKey, COSEMessage, COSETypes, Recipient, Signer, VerifyError


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
        assert countersignature.protected[1] == -8  # alg: "EdDSA"
        assert countersignature.unprotected[4] == b"01"  # kid: b"01"

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
        assert countersignature.protected[1] == -8  # alg: "EdDSA"
        assert countersignature.unprotected[4] == b"01"  # kid: b"01"

        try:
            sig = COSEMessage.loads(countersigned2).counterverify(pub_key2)
        except Exception as err:
            pytest.fail(f"failed to verify: {err}")
        countersignature = COSEMessage.from_cose_signature(sig)
        assert countersignature.protected[1] == -7  # alg: "ES256"
        assert countersignature.unprotected[4] == b"02"  # kid: b"02"

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
        assert countersignature.protected[1] == -8  # alg: "EdDSA"

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
        assert countersignature.protected[1] == -8  # alg: "EdDSA"
        assert countersignature.unprotected[4] == b"01"  # kid: b"01"

    @pytest.mark.parametrize(
        "type, msg, err_msg",
        [
            (COSETypes.MAC0, [], "Invalid COSE message."),
            (COSETypes.MAC0, [{}, {}, b""], "The protected headers should be bytes."),
            (COSETypes.MAC0, [b"", b"", b""], "The unprotected headers should be Dict[int, Any]."),
            (COSETypes.MAC0, [b"", {11: {}}, b""], "The countersignature should be array."),
            (COSETypes.MAC0, [b"", {11: []}, b""], "Invalid countersignature."),
            (COSETypes.MAC0, [b"", {11: [b""]}, b""], "Invalid COSE message."),
            (COSETypes.MAC0, [b"", {11: [""]}, b""], "Invalid countersignature."),
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
        data.value[2] = detached_payload
        reverted_cose_message = COSEMessage.loads(cbor2.dumps(data))
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
        assert countersignature.protected[1] == -8  # alg: "EdDSA"
        assert countersignature.unprotected[4] == b"01"  # kid: b"01"
