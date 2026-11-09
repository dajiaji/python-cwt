"""
Tests for rejecting CBOR maps with duplicate keys (RFC 9052 Section 3).
"""

import cbor2
import pytest
from cbor2 import CBORTag, dumps

import cwt
from cwt import COSE, COSEKey, COSEMessage, DecodeError, EncryptedCOSEKey, Recipient

# {1: 4, 1: 5}: a map with the same label (alg) twice.
DUP_ALG_MAP = b"\xa2" + dumps(1) + dumps(4) + dumps(1) + dumps(5)
# {4: b"a", 4: b"poc"}: a map with the same label (kid) twice.
DUP_KID_MAP = b"\xa2" + dumps(4) + dumps(b"a") + dumps(4) + dumps(b"poc")


@pytest.fixture
def mac_key():
    return COSEKey.from_symmetric_key(alg="HS256", kid="poc")


class TestDuplicateMapKeys:
    def test_decode_mac0_with_duplicated_protected_header_label(self, mac_key):
        tag = mac_key.sign(dumps(["MAC0", DUP_ALG_MAP, b"", b"payload"]))
        wire = dumps(CBORTag(17, [DUP_ALG_MAP, {}, b"payload", tag]))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode_with_headers(wire, mac_key)
            pytest.fail("decode_with_headers() should fail.")
        assert "Failed to decode." in str(err.value)
        assert isinstance(err.value.__cause__, cbor2.CBORDecodeError)

    def test_decode_mac0_with_duplicated_unprotected_header_label(self, mac_key):
        protected = dumps({1: 5})
        tag = mac_key.sign(dumps(["MAC0", protected, b"", b"payload"]))
        wire = b"\xd1\x84" + dumps(protected) + DUP_KID_MAP + dumps(b"payload") + dumps(tag)
        with pytest.raises(DecodeError) as err:
            COSE.new().decode_with_headers(wire, mac_key)
            pytest.fail("decode_with_headers() should fail.")
        assert "Failed to decode." in str(err.value)

    def test_decode_sign1_with_duplicated_protected_header_label(self):
        # {1: -7, 1: -7}: ES256 twice.
        protected = b"\xa2" + dumps(1) + dumps(-7) + dumps(1) + dumps(-7)
        key = COSEKey.generate_symmetric_key(alg="HS256")  # never reached; decoding fails first.
        wire = dumps(CBORTag(18, [protected, {}, b"payload", b"\x00" * 64]))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(wire, key)
            pytest.fail("decode() should fail.")
        assert "Failed to decode." in str(err.value)

    def test_decode_cwt_with_duplicated_claim_keys(self, mac_key):
        # {1: "a", 1: "b"}: iss twice.
        claims = b"\xa2" + dumps(1) + dumps("a") + dumps(1) + dumps("b")
        token = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True).encode_and_mac(claims, mac_key)
        with pytest.raises(DecodeError) as err:
            cwt.decode(token, mac_key)
            pytest.fail("decode() should fail.")
        assert "Failed to decode." in str(err.value)

    def test_cose_key_from_bytes_with_duplicated_labels(self):
        # {1: 4, 1: 4, -1: k}: kty twice.
        key_data = b"\xa3" + dumps(1) + dumps(4) + dumps(1) + dumps(4) + dumps(-1) + dumps(b"x" * 32)
        with pytest.raises(cbor2.CBORDecodeError):
            COSEKey.from_bytes(key_data)
            pytest.fail("from_bytes() should fail.")

    def test_encrypted_cose_key_to_cose_key_with_duplicated_labels(self):
        enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="enc")
        cose = COSE()

        def encrypt(key_data: bytes) -> list:
            p = {1: enc_key.alg}
            u = {4: enc_key.kid, 5: enc_key.generate_nonce()}
            return cose.encode_and_encrypt(key_data, enc_key, p, u, out="cbor2/CBORTag").value

        # alg: HS256, k: b"x" * 32
        rest = dumps(3) + dumps(5) + dumps(-1) + dumps(b"x" * 32)

        # {1: 4, 3: 5, -1: k}: without duplicates, the key can be decrypted and decoded.
        assert EncryptedCOSEKey.to_cose_key(encrypt(b"\xa3" + dumps(1) + dumps(4) + rest), enc_key).kty == 4

        # {1: 4, 1: 4, 3: 5, -1: k}: kty twice.
        with pytest.raises(cbor2.CBORDecodeError):
            EncryptedCOSEKey.to_cose_key(encrypt(b"\xa4" + dumps(1) + dumps(4) + dumps(1) + dumps(4) + rest), enc_key)
            pytest.fail("to_cose_key() should fail.")

    def test_recipient_from_list_with_duplicated_protected_header_label(self):
        with pytest.raises(cbor2.CBORDecodeError):
            Recipient.from_list([DUP_ALG_MAP, {}, b""])
            pytest.fail("from_list() should fail.")

    def test_cose_message_loads_with_duplicated_unprotected_header_label(self):
        wire = b"\xd1\x84" + dumps(b"") + DUP_KID_MAP + dumps(b"payload") + dumps(b"tag")
        with pytest.raises(cbor2.CBORDecodeError):
            COSEMessage.loads(wire)
            pytest.fail("loads() should fail.")
