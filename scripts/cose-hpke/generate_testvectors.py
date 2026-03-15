#!/usr/bin/env python3
"""Generate tests/vectors/testvectors.txt including PSK vectors with psk_id in protected header."""

import os

import cbor2

from cwt import COSE, COSEKey, Recipient

# PSK parameters from the RFC test vector section
PSK = bytes.fromhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
PSK_ID = bytes.fromhex("456e6e796e20447572696e206172616e204d6f726961")

PLAINTEXT = b"hpke test payload"

# External parameter values from the RFC
EXT_AAD = b"external-aad"
EXT_INFO = b"external-info"
EXT_HPKE_AAD = b"external-hpke-aad"

# KE private keys (COSE_Key CBOR hex)
HPKE_0_KE_KEY = "a70102024d626f622d68706b655f305f6b6503182e200121582064ea61f745f7deed186d697a4c89715932755017766348b0443a60aac450b5a622582088f53a4cbbcfcc1bf0b33d5dc60f789a7f495244f57c158a8ceed5179639152b235820e8de39325f3c0be02442076c470a46bca742de9bc2be453ec1dc049dda1f6ca3"  # noqa: E501
HPKE_1_KE_KEY = "a70102024d626f622d68706b655f315f6b6503182f200221583003fcd256d1fd79ce8d6d29e3cb72a823380e1c655aa2ce211721245873bacb76eacd6e28f4557fed255246a76fdd61b82258304dd4aa71088792b44e00970c2f269c1eb546e848a6df2946e4409777deb6d7b77803a383c9e87757cef9f18910a1f76423583035172a2ccec0f1d1af547b811754e01de5406257ca808f2fabcbca5cbf7a4d22b951fc1d4da0e89e8608fde30d2f6706"  # noqa: E501
HPKE_2_KE_KEY = "a70102024d626f622d68706b655f325f6b6503183020032158420033db899e500ac6f1fb7a9e23f16a363e41b6d1f6dd5562c4faaa0491f1a74cbdbd039ff2b5824842d4da26c36173bc31ba2d1672699d871fdca27b9af0020bb580225842012ecb4d569869085618ce0a4e0f82fe9b618dae8b678e26e7a1ed8d8b9bdf7ffcd32dfdee1bd85ee52097866c4f493a3174e6abb6b365057d212ce3d84a5010a6df235842019f28872f689d9c3a8018712e453a23beac37cb86c87e2c5a99d7e3901f2e4f4995fae274ca07748a7076d0ecae6466a7c3cdbc55d233544a59d22d3e4dde1d4b5f"  # noqa: E501
HPKE_3_KE_KEY = "a60101024d626f622d68706b655f335f6b6503183120042158202d925acfd0ee359a68565b619165985a7108f7b1771131e26f11d24177dc9a3c23582060cb9ff63744acdac02a48527dfc2810fc49bc1223a240d870fa2d668c891155"  # noqa: E501
HPKE_4_KE_KEY = "a60101024d626f622d68706b655f345f6b650318322004215820a5922a701eebdf665a7877e32b0651db5d3ad8eb4be792f2dfd9d9ac5d04956123582000f28ee18a4ddcdd4f318dd88ba71efe0bb68002015e9c4879e99edf4e9c4b60"  # noqa: E501
HPKE_5_KE_KEY = "a60101024d626f622d68706b655f355f6b6503183320052158384489c1479ccd35343a90b3e1cb4922f73d9d611f12bf4abe9f76fcac6a6a974c0941fa602dfc29fb5c52b3191ea896162718d2ddbc97097e235838785cb877d73f034edaaa14d66dc3e10bc28d3ee5a290310c89eab7e347a82218874963600cf36850a389325fcbb6e4477dcc0f1b65e860d9"  # noqa: E501
HPKE_6_KE_KEY = "a60101024d626f622d68706b655f365f6b650318342005215838253b435291775cff909b2227b8bd6f539f521368b33871022f95713b4433df21becfffeaba9d63e839e43413e92689ead254feae3d7aa8e72358382c6894f63ec5d05047370d9415d4c0cd53ee2633926596788a41b5ff5368733b7d9499c391b08ed7c1c3d750c4c5af2ff03a44278c7c40b6"  # noqa: E501
HPKE_7_KE_KEY = "a70102024d626f622d68706b655f375f6b65031835200121582055137ef3179b4bba4326a5e73ae0966d92d2ccc7e1714a66fba562a1c597a08d2258201daa17ff95d717128dc944069f4060af5981575734f1f847e6bd6bc30603cd6123582073294f0f394f08becf7358ea89c0cda596cbd9705a6b7c6f0ae8d70a9a85a913"  # noqa: E501

# Encrypt0 private keys (COSE_Key CBOR hex)
HPKE_0_KEY = "a70102024e626f622d68706b655f302d696e7403182320012158206699b067898b7d2d37db0da3aecad4bdac1558870b47d67d080d6049fb81752f225820b01b6da1f210f46e20e2b552a80f4f6b9a3adad34a6701f73fbbeffb174cf7412358206716e93d6594fbfd27016daada9ccc8e6ba2eea0e103e3d7ae22278f6dfe124a"  # noqa: E501
HPKE_1_KEY = "a70102024e626f622d68706b655f312d696e7403182520022158308309a370b333f956c1cff9d94e1ef8aacc2808ca898fec0476d9c132893704a2a4ecc88bd002e2c71383b97bb3ab65822258304b2a3e1b2fc832c136aee1632f967b31f5afd0a32c8c9766d0e9d0e4e2560a905278b0d9965898b3fe4d2165cfa1b1c0235830bde0361bbbf278ff3286a36897b2e674286870981ef471c2c81b55a3b82827800d32b34da68993cd590ff06e0788aeaf"  # noqa: E501
HPKE_2_KEY = "a70102024e626f622d68706b655f322d696e740318272003215842003c20a6d2990dac871dec57d8f31283ca99b9958a00e92ba43b1ff9186813f750b01333ef1f3119601875065599aa48884425480a4d20e8e39bc84e98f745d91ed72258420058edb9dbccddc1594dc9003ab39886babd7ef7d0046aa72eae0f9c67b794c251c8a2309ae05f6f1cf4ac06045ecd45bc335d5c316936e3968e6ed42211bfdaa859235842010c50be4e0322d8bcb1424750f6ed3b22bcbe25ae9745a868688dcbbab97f522f5a95d0712b8d9ff48a5be6650179fd4e59913c76b1b28af9605ddb294756c2effd"  # noqa: E501
HPKE_3_KEY = "a60101024e626f622d68706b655f332d696e74031829200421582085eb6351a4e93a49953e1e23ade9504af68a73196a823c9a0654bf98c7536a7f235820f0b8ece6e3938430f36798eeea8206d0ac5e0577349ad63843cbbb63bc90b849"  # noqa: E501
HPKE_4_KEY = "a60101024e626f622d68706b655f342d696e7403182a20042158200191a45e7240233a4bda72ac8b38283aea336c863c7d5856b7df263038bc69072358200838e90c3407649faf0bd7eeb3e5a9fd7c643e4cb72b91997fc81d26d2f1de49"  # noqa: E501
HPKE_5_KEY = "a60101024e626f622d68706b655f352d696e7403182b2005215838fa09d4a5d1fa3a7b2b6de43b08c715283d7425b80bf8b628b07d0d077283aa9c1507354e98c087688e8cfe7220be5e2d44509b2fd53b24e9235838b07f1d8cb1d2f3d5ba62c0ad5a1791e0fe79f6fdb9f49910274aa184855b67850ab2a53b39b131d07bc3d4e80a4f83b1c9f8f5f97f1fa598"  # noqa: E501
HPKE_6_KEY = "a60101024e626f622d68706b655f362d696e7403182c20052158380aff5f4a86fc468a25b7715d066628125dad13e4243f242cd6585f89f7371a55cfc3cf42cd3405a78dd380b4e9f4d47880c684deaa3f8aa923583898b6c98f0d48162ecc4c0f5e09c97246b03564a2672e12496f0f7a0d0576fbbdfb287b5a868e5b569a55b7d3765e5685feb7270471b13392"  # noqa: E501
HPKE_7_KEY = "a70102024e626f622d68706b655f372d696e7403182d2001215820df717fb8deae1b58b754487c5432c8ec9a140dd11bcc7cd65cbe4b728e9263d6225820a8528d6143673203144a9636ea065c60761390916f2218c8db958a64e263d3e02358202343a73ed3dc2b5e110d734c8d5e7a8b7fea63849e78a8db3da48a65ecdb720e"  # noqa: E501

# KE keys and their L0 content algorithm names
KE_KEYS = [
    (HPKE_0_KE_KEY, "A128GCM"),
    (HPKE_1_KE_KEY, "A256GCM"),
    (HPKE_2_KE_KEY, "A256GCM"),
    (HPKE_3_KE_KEY, "A128GCM"),
    (HPKE_4_KE_KEY, "ChaCha20/Poly1305"),
    (HPKE_5_KE_KEY, "A256GCM"),
    (HPKE_6_KE_KEY, "A256GCM"),
    (HPKE_7_KE_KEY, "A256GCM"),
]

E0_KEYS = [
    HPKE_0_KEY,
    HPKE_1_KEY,
    HPKE_2_KEY,
    HPKE_3_KEY,
    HPKE_4_KEY,
    HPKE_5_KEY,
    HPKE_6_KEY,
    HPKE_7_KEY,
]

# KE parameter combinations: (ext_aad, ext_info, hpke_aad)
KE_COMBOS = [
    (b"", b"", b"", "default aad, default info, default hpke aad"),
    (b"", b"", EXT_HPKE_AAD, "default aad, default info, external hpke aad"),
    (EXT_AAD, b"", b"", "external aad, default info, default hpke aad"),
    (EXT_AAD, b"", EXT_HPKE_AAD, "external aad, default info, external hpke aad"),
    (b"", EXT_INFO, b"", "default aad, external info, default hpke aad"),
    (b"", EXT_INFO, EXT_HPKE_AAD, "default aad, external info, external hpke aad"),
    (EXT_AAD, EXT_INFO, b"", "external aad, external info, default hpke aad"),
    (EXT_AAD, EXT_INFO, EXT_HPKE_AAD, "external aad, external info, external hpke aad"),
]

# Encrypt0 parameter combinations: (ext_aad, hpke_info)
E0_COMBOS = [
    (b"", b"", "default aad and default info"),
    (EXT_AAD, b"", "external aad and default info"),
    (b"", EXT_INFO, "default aad and external info"),
    (EXT_AAD, EXT_INFO, "external aad and external info"),
]


def extract_public_key(key_hex):
    """Extract public key from COSE_Key hex (remove private key -4/d)."""
    key_data = cbor2.loads(bytes.fromhex(key_hex))
    rpk_data = {k: v for k, v in key_data.items() if k != -4}
    return rpk_data, key_data


def generate_ke_vector(key_hex, content_alg_name, ext_aad, extra_info, hpke_aad, psk=None):
    """Generate a KE (COSE_Encrypt) vector."""
    rpk_data, full_key_data = extract_public_key(key_hex)
    rpk = COSEKey.new(rpk_data)
    kid = full_key_data[2]
    ke_alg = full_key_data[3]

    rec_protected = {1: ke_alg}
    if psk is not None:
        rec_protected[-5] = PSK_ID

    r = Recipient.new(
        protected=rec_protected,
        unprotected={4: kid},
        recipient_key=rpk,
        hpke_psk=psk,
        extra_info=extra_info,
        hpke_aad=hpke_aad,
    )

    enc_key = COSEKey.from_symmetric_key(alg=content_alg_name)
    sender = COSE.new()
    encoded = sender.encode_and_encrypt(
        PLAINTEXT,
        enc_key,
        protected={1: enc_key.alg},
        recipients=[r],
        external_aad=ext_aad,
    )

    # Verify
    full_key = COSEKey.new(full_key_data)
    result = COSE.new().decode(
        encoded,
        full_key,
        external_aad=ext_aad,
        extra_info=extra_info,
        hpke_aad=hpke_aad,
        hpke_psk=psk,
    )
    assert result == PLAINTEXT, "Decryption verification failed!"

    return encoded.hex()


def generate_e0_vector(key_hex, ext_aad, hpke_info, psk=None):
    """Generate an Encrypt0 (COSE_Encrypt0) vector."""
    rpk_data, full_key_data = extract_public_key(key_hex)
    rpk = COSEKey.new(rpk_data)
    kid = full_key_data[2]
    alg = full_key_data[3]

    protected = {1: alg}
    if psk is not None:
        protected[-5] = PSK_ID

    sender = COSE.new()
    encoded = sender.encode_and_encrypt(
        PLAINTEXT,
        rpk,
        protected=protected,
        unprotected={4: kid},
        hpke_psk=psk,
        external_aad=ext_aad,
        hpke_info=hpke_info,
    )

    # Verify
    full_key = COSEKey.new(full_key_data)
    result = COSE.new().decode(
        encoded,
        full_key,
        external_aad=ext_aad,
        hpke_info=hpke_info,
        hpke_psk=psk,
    )
    assert result == PLAINTEXT, "Decryption verification failed!"

    return encoded.hex()


def main():
    out_path = os.path.join(os.path.dirname(__file__), "..", "tests", "vectors", "testvectors.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    lines = []

    # --- KE base vectors ---
    for i, (key_hex, content_alg_name) in enumerate(KE_KEYS):
        lines.append(f"HPKE-{i}-KE COSE_Key:: {key_hex}")
        lines.append("")
        for ext_aad, extra_info, hpke_aad, desc in KE_COMBOS:
            lines.append("")
            lines.append(f"HPKE-{i}-KE with {desc}")
            lines.append("")
            ct = generate_ke_vector(key_hex, content_alg_name, ext_aad, extra_info, hpke_aad)
            lines.append(f"Ciphertext: {ct}")
            lines.append("")
        lines.append("")

    # --- Encrypt0 base vectors ---
    for i, key_hex in enumerate(E0_KEYS):
        lines.append(f"HPKE-{i} COSE_Key: {key_hex}")
        lines.append("")
        for ext_aad, hpke_info, desc in E0_COMBOS:
            lines.append("")
            lines.append(f"HPKE-{i} Encrypt0 with {desc}")
            lines.append("")
            ct = generate_e0_vector(key_hex, ext_aad, hpke_info)
            lines.append(f"Ciphertext: {ct}")
            lines.append("")
        lines.append("")

    # --- KE PSK vectors ---
    for i, (key_hex, content_alg_name) in enumerate(KE_KEYS):
        lines.append(f"HPKE-{i}-KE COSE_Key: {key_hex}")
        lines.append("")
        for ext_aad, extra_info, hpke_aad, desc in KE_COMBOS:
            lines.append("")
            lines.append(f"HPKE-{i}-KE KE+PSK with {desc}")
            lines.append("")
            ct = generate_ke_vector(key_hex, content_alg_name, ext_aad, extra_info, hpke_aad, psk=PSK)
            lines.append(f"Ciphertext: {ct}")
            lines.append("")
        lines.append("")

    # --- Encrypt0 PSK vectors ---
    for i, key_hex in enumerate(E0_KEYS):
        lines.append(f"HPKE-{i} COSE_Key:: {key_hex}")
        lines.append("")
        for ext_aad, hpke_info, desc in E0_COMBOS:
            lines.append("")
            lines.append(f"HPKE-{i} Encrypt0+PSK with {desc}")
            lines.append("")
            ct = generate_e0_vector(key_hex, ext_aad, hpke_info, psk=PSK)
            lines.append(f"Ciphertext: {ct}")
            lines.append("")
        lines.append("")

    # Remove trailing blank lines
    while lines and lines[-1] == "":
        lines.pop()

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {out_path}")

    # Count vectors
    ct_count = sum(1 for line in lines if line.startswith("Ciphertext:"))
    print(f"Total vectors: {ct_count}")
    print(f"  KE base: {len(KE_KEYS) * len(KE_COMBOS)}")
    print(f"  Encrypt0 base: {len(E0_KEYS) * len(E0_COMBOS)}")
    print(f"  KE PSK: {len(KE_KEYS) * len(KE_COMBOS)}")
    print(f"  Encrypt0 PSK: {len(E0_KEYS) * len(E0_COMBOS)}")


if __name__ == "__main__":
    main()
