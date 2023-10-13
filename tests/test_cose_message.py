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
