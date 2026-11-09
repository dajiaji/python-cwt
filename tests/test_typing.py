"""
Tests for static return types of factory class methods.

``typing.assert_type`` is a no-op at runtime, but mypy (run via pre-commit)
checks that each factory is annotated to return ``Self``.
"""

from typing import assert_type

from cwt import COSE, CWT, Claims, COSEKey, COSEMessage, Signer
from cwt.recipients import Recipients

from .utils import key_path


class MyCOSE(COSE):
    pass


class MyCWT(CWT):
    pass


class MyClaims(Claims):
    pass


class MySigner(Signer):
    pass


class MyRecipients(Recipients):
    pass


class MyCOSEMessage(COSEMessage):
    pass


class TestTyping:
    """
    Tests for return types of factory class methods.
    """

    def test_typing_cose_and_cwt_new(self) -> None:
        assert isinstance(assert_type(COSE.new(), COSE), COSE)
        assert isinstance(assert_type(MyCOSE.new(), MyCOSE), MyCOSE)
        assert isinstance(assert_type(CWT.new(), CWT), CWT)
        assert isinstance(assert_type(MyCWT.new(), MyCWT), MyCWT)

    def test_typing_claims(self) -> None:
        assert isinstance(assert_type(Claims.new({1: "coaps://as.example"}), Claims), Claims)
        assert isinstance(assert_type(MyClaims.new({1: "coaps://as.example"}), MyClaims), MyClaims)
        assert isinstance(assert_type(Claims.from_json({"iss": "coaps://as.example"}), Claims), Claims)
        assert isinstance(assert_type(MyClaims.from_json({"iss": "coaps://as.example"}), MyClaims), MyClaims)

    def test_typing_signer(self) -> None:
        with open(key_path("private_key_ed25519.pem")) as key_file:
            pem = key_file.read()
        jwk = {
            "kty": "OKP",
            "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "01",
            "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            "alg": "EdDSA",
        }
        key = COSEKey.from_pem(pem, kid="01")
        assert isinstance(assert_type(Signer.new(cose_key=key), Signer), Signer)
        assert isinstance(assert_type(MySigner.new(cose_key=key), MySigner), MySigner)
        assert isinstance(assert_type(Signer.from_jwk(jwk), Signer), Signer)
        assert isinstance(assert_type(MySigner.from_jwk(jwk), MySigner), MySigner)
        assert isinstance(assert_type(Signer.from_pem(pem, kid="01"), Signer), Signer)
        assert isinstance(assert_type(MySigner.from_pem(pem, kid="01"), MySigner), MySigner)

    def test_typing_recipients(self) -> None:
        assert isinstance(assert_type(Recipients.from_list([]), Recipients), Recipients)
        assert isinstance(assert_type(MyRecipients.from_list([]), MyRecipients), MyRecipients)

    def test_typing_cose_message(self) -> None:
        with open(key_path("private_key_ed25519.pem")) as key_file:
            key = COSEKey.from_pem(key_file.read(), kid="01")
        encoded = COSE.new(alg_auto_inclusion=True).encode_and_sign(b"Hello world!", key)
        assert isinstance(encoded, bytes)
        signature = [b"", {}, b""]
        assert isinstance(assert_type(COSEMessage.loads(encoded), COSEMessage), COSEMessage)
        assert isinstance(assert_type(MyCOSEMessage.loads(encoded), MyCOSEMessage), MyCOSEMessage)
        assert isinstance(assert_type(COSEMessage.from_cose_signature(signature), COSEMessage), COSEMessage)
        assert isinstance(assert_type(MyCOSEMessage.from_cose_signature(signature), MyCOSEMessage), MyCOSEMessage)
        assert isinstance(assert_type(COSEMessage.from_cose_recipient(signature), COSEMessage), COSEMessage)
        assert isinstance(assert_type(MyCOSEMessage.from_cose_recipient(signature), MyCOSEMessage), MyCOSEMessage)
