"""Tests for COSE-HPKE test vectors from draft-ietf-cose-hpke Appendix C.

Test vectors are loaded from tests/vectors/testvectors.txt.
"""

import os
import re

import cbor2
import pytest

from cwt import COSE, COSEKey

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "vectors", "testvectors.txt")

# Common PSK parameters from the RFC test vectors
PSK = bytes.fromhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
PSK_ID = bytes.fromhex("456e6e796e20447572696e206172616e204d6f726961")


def _parse_testvectors(path):
    """Parse testvectors.txt and return structured test data.

    Returns four lists:
      ke_vectors:          [(key_hex, ct_hex, ext_aad, extra_info, hpke_aad, label), ...]
      encrypt0_vectors:    [(key_hex, ct_hex, ext_aad, hpke_info, label), ...]
      ke_psk_vectors:      [(key_hex, ct_hex, ext_aad, extra_info, hpke_aad, label), ...]
      encrypt0_psk_vectors:[(key_hex, ct_hex, ext_aad, hpke_info, label), ...]
    """
    ke_vectors = []
    encrypt0_vectors = []
    ke_psk_vectors = []
    encrypt0_psk_vectors = []

    with open(path) as f:
        lines = f.readlines()

    current_key = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Key line: "HPKE-X[-KE] COSE_Key[:][:] <hex>"
        key_match = re.match(r"^(HPKE-\d+(?:-KE)?)\s+COSE_Key::?\s+([0-9a-fA-F]+)$", line)
        if key_match:
            current_key = key_match.group(2)
            i += 1
            continue

        # KE+PSK vector: "HPKE-X-KE KE+PSK with ..."
        ke_psk_match = re.match(
            r"^(HPKE-\d+-KE)\s+KE\+PSK\s+with\s+"
            r"(default|external)\s+aad,\s+"
            r"(default|external)\s+info,\s+"
            r"(default|external)\s+hpke\s+aad$",
            line,
        )
        if ke_psk_match:
            ext_aad = b"external-aad" if ke_psk_match.group(2) == "external" else b""
            ext_info = b"external-info" if ke_psk_match.group(3) == "external" else b""
            hpke_aad = b"external-hpke-aad" if ke_psk_match.group(4) == "external" else b""
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            ct_match = re.match(r"^Ciphertext:\s+([0-9a-fA-F]+)$", lines[i].strip())
            if ct_match and current_key:
                label = (
                    f"{ke_psk_match.group(1)}-PSK-"
                    f"{ke_psk_match.group(2)}-aad-"
                    f"{ke_psk_match.group(3)}-info-"
                    f"{ke_psk_match.group(4)}-hpke-aad"
                )
                ke_psk_vectors.append((current_key, ct_match.group(1), ext_aad, ext_info, hpke_aad, label))
            i += 1
            continue

        # KE base vector: "HPKE-X-KE with ..."
        ke_match = re.match(
            r"^(HPKE-\d+-KE)\s+with\s+"
            r"(default|external)\s+aad,\s+"
            r"(default|external)\s+info,\s+"
            r"(default|external)\s+hpke\s+aad$",
            line,
        )
        if ke_match:
            ext_aad = b"external-aad" if ke_match.group(2) == "external" else b""
            ext_info = b"external-info" if ke_match.group(3) == "external" else b""
            hpke_aad = b"external-hpke-aad" if ke_match.group(4) == "external" else b""
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            ct_match = re.match(r"^Ciphertext:\s+([0-9a-fA-F]+)$", lines[i].strip())
            if ct_match and current_key:
                label = (
                    f"{ke_match.group(1)}-"
                    f"{ke_match.group(2)}-aad-"
                    f"{ke_match.group(3)}-info-"
                    f"{ke_match.group(4)}-hpke-aad"
                )
                ke_vectors.append((current_key, ct_match.group(1), ext_aad, ext_info, hpke_aad, label))
            i += 1
            continue

        # Encrypt0+PSK vector: "HPKE-X Encrypt0+PSK with ..."
        e0_psk_match = re.match(
            r"^(HPKE-\d+)\s+Encrypt0\+PSK\s+with\s+" r"(default|external)\s+aad\s+and\s+" r"(default|external)\s+info$",
            line,
        )
        if e0_psk_match:
            ext_aad = b"external-aad" if e0_psk_match.group(2) == "external" else b""
            hpke_info = b"external-info" if e0_psk_match.group(3) == "external" else b""
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            ct_match = re.match(r"^Ciphertext:\s+([0-9a-fA-F]+)$", lines[i].strip())
            if ct_match and current_key:
                label = f"{e0_psk_match.group(1)}-Encrypt0-PSK-" f"{e0_psk_match.group(2)}-aad-" f"{e0_psk_match.group(3)}-info"
                encrypt0_psk_vectors.append((current_key, ct_match.group(1), ext_aad, hpke_info, label))
            i += 1
            continue

        # Encrypt0 base vector: "HPKE-X Encrypt0 with ..."
        e0_match = re.match(
            r"^(HPKE-\d+)\s+Encrypt0\s+with\s+" r"(default|external)\s+aad\s+and\s+" r"(default|external)\s+info$",
            line,
        )
        if e0_match:
            ext_aad = b"external-aad" if e0_match.group(2) == "external" else b""
            hpke_info = b"external-info" if e0_match.group(3) == "external" else b""
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            ct_match = re.match(r"^Ciphertext:\s+([0-9a-fA-F]+)$", lines[i].strip())
            if ct_match and current_key:
                label = f"{e0_match.group(1)}-Encrypt0-" f"{e0_match.group(2)}-aad-" f"{e0_match.group(3)}-info"
                encrypt0_vectors.append((current_key, ct_match.group(1), ext_aad, hpke_info, label))
            i += 1
            continue

        i += 1

    return ke_vectors, encrypt0_vectors, ke_psk_vectors, encrypt0_psk_vectors


# Parse vectors once at module load time
_KE, _E0, _KE_PSK, _E0_PSK = _parse_testvectors(VECTORS_PATH)


class TestCOSEHPKEKEVectors:
    """Test vectors for COSE-HPKE Key Encryption (COSE_Encrypt)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, extra_info, hpke_aad",
        [v[:5] for v in _KE],
        ids=[v[5] for v in _KE],
    )
    def test_ke_vector(self, key_hex, ct_hex, external_aad, extra_info, hpke_aad):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(ct, key, external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad)
        assert result == b"hpke test payload"


class TestCOSEHPKEEncrypt0Vectors:
    """Test vectors for COSE-HPKE Integrated Encryption (COSE_Encrypt0)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, hpke_info",
        [v[:4] for v in _E0],
        ids=[v[4] for v in _E0],
    )
    def test_encrypt0_vector(self, key_hex, ct_hex, external_aad, hpke_info):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(ct, key, external_aad=external_aad, hpke_info=hpke_info)
        assert result == b"hpke test payload"


@pytest.mark.skip(
    reason="PSK test vectors do not include psk_id in the protected header "
    "as required by the updated draft-ietf-cose-hpke. "
    "Vectors need to be regenerated with psk_id in the protected header."
)
class TestCOSEHPKEKEPSKVectors:
    """Test vectors for COSE-HPKE Key Encryption with PSK (COSE_Encrypt)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, extra_info, hpke_aad",
        [v[:5] for v in _KE_PSK],
        ids=[v[5] for v in _KE_PSK],
    )
    def test_ke_psk_vector(self, key_hex, ct_hex, external_aad, extra_info, hpke_aad):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(
            ct,
            key,
            external_aad=external_aad,
            extra_info=extra_info,
            hpke_aad=hpke_aad,
            hpke_psk=PSK,
        )
        assert result == b"hpke test payload"


@pytest.mark.skip(
    reason="PSK test vectors do not include psk_id in the protected header "
    "as required by the updated draft-ietf-cose-hpke. "
    "Vectors need to be regenerated with psk_id in the protected header."
)
class TestCOSEHPKEEncrypt0PSKVectors:
    """Test vectors for COSE-HPKE Integrated Encryption with PSK (COSE_Encrypt0)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, hpke_info",
        [v[:4] for v in _E0_PSK],
        ids=[v[4] for v in _E0_PSK],
    )
    def test_encrypt0_psk_vector(self, key_hex, ct_hex, external_aad, hpke_info):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(ct, key, external_aad=external_aad, hpke_info=hpke_info, hpke_psk=PSK)
        assert result == b"hpke test payload"
