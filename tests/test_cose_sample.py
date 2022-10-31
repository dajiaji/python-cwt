from secrets import token_bytes

import pytest

from cwt import COSE, COSEKey, Recipient, Signer


class TestCOSESample:
    """
    Tests for samples on COSE Usage Examples.
    """

    def test_cose_usage_examples_cose_mac0(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")

        # The sender side:
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode_and_mac(b"Hello world!", mac_key)

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, mac_key)

        # variation
        sender = COSE.new()
        encoded2 = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={"alg": "HS256"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == recipient.decode(encoded2, mac_key)

        encoded3 = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={1: 5},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == recipient.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac_direct(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")

        # The sender side:
        r = Recipient.from_jwk({"alg": "direct"})
        r.apply(mac_key)

        sender = COSE.new()
        encoded = sender.encode_and_mac(b"Hello world!", mac_key, recipients=[r])

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, mac_key)

        # variation
        r2 = Recipient.new(unprotected={"alg": "direct"})
        r2.apply(mac_key)
        encoded2 = sender.encode_and_mac(b"Hello world!", mac_key, recipients=[r2])
        assert b"Hello world!" == recipient.decode(encoded2, mac_key)

        r3 = Recipient.new(unprotected={1: -6})
        r3.apply(mac_key)
        encoded3 = sender.encode_and_mac(b"Hello world!", mac_key, recipients=[r3])
        assert b"Hello world!" == recipient.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac_direct_hkdf_sha_256(self):

        shared_material = token_bytes(32)
        shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "salt": "aabbccddeeffgghh",
            },
        )
        mac_key = r.apply(shared_key, context={"alg": "HS256"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            key=mac_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, shared_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_mac_aes_key_wrap(self):

        # The sender side:
        mac_key = COSEKey.from_symmetric_key(alg="HS512")
        r = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
            },
        )
        r.apply(mac_key)
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(b"Hello world!", key=mac_key, recipients=[r])

        # The recipient side:
        recipient = COSE.new()
        shared_key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        assert b"Hello world!" == recipient.decode(encoded, shared_key)

    def test_cose_usage_examples_cose_mac_ecdh_direct_hkdf_p256(self):

        # The sender side:
        # The following key is provided by the recipient in advance.
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        r = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "P-256",
            },
        )
        mac_key = r.apply(recipient_key=pub_key, context={"alg": "HS256"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            key=mac_key,
            recipients=[r],
        )

        # The recipient side:
        # The following key is the private key of the above pub_key.
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        recipient = COSE.new()
        # The enc_key will be derived in decode() with priv_key and
        # the sender's public key which is conveyed as the recipient
        # information structure in the COSE Encrypt message (encoded).
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_mac_ecdh_direct_hkdf_x25519(self):

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "X25519",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
            }
        )
        mac_key = r.apply(recipient_key=pub_key, context={"alg": "HS256"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            key=mac_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_mac_ecdh_direct_hkdf_x448(self):

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "X448",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X448",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
            }
        )
        mac_key = r.apply(recipient_key=pub_key, context={"alg": "HS256"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            key=mac_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X448",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
                "d": "rJJRG3nshyCtd9CgXld8aNaB9YXKR0UOi7zj7hApg9YH4XdBO0G8NcAFNz_uPH2GnCZVcSDgV5c",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_mac_ecdh_ss_a128kw(self):

        # The sender side:
        mac_key = COSEKey.from_symmetric_key(alg="HS256")
        r = Recipient.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
                "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
                "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
            }
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        r.apply(mac_key, recipient_key=pub_key, context={"alg": "HS256"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            key=mac_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_encrypt0(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

        # The sender side:
        nonce = enc_key.generate_nonce()
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(b"Hello world!", enc_key, nonce=nonce)

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, enc_key)

        # variation
        sender = COSE.new()
        encoded2 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            protected={"alg": "ChaCha20/Poly1305"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == recipient.decode(encoded2, enc_key)

        encoded3 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            protected={1: 24},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == recipient.decode(encoded3, enc_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_encrypt0_hpke(self):
        # The sender side:
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                # "alg": "HPKE",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                    2: 0x0001,  # kdf: HKDF-SHA256
                    3: 0x0001,  # aead: AES-128-GCM
                },
            },
        )

        # print(encoded.hex())

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                # "alg": "HPKE",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    def test_cose_usage_examples_cose_encrypt(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

        # The sender side:
        nonce = enc_key.generate_nonce()
        r = Recipient.from_jwk({"alg": "direct"})
        r.apply(enc_key)

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, enc_key)

        # variation
        r = Recipient.new(unprotected={"alg": "direct"})
        r.apply(enc_key)
        encoded2 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[r],
        )
        assert b"Hello world!" == recipient.decode(encoded2, enc_key)

        encoded3 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[r],
        )
        assert b"Hello world!" == recipient.decode(encoded3, enc_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_encrypt_hpke(self):

        # The sender side:
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        r = Recipient.new(
            protected={
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                    2: 0x0001,  # kdf: HKDF-SHA256
                    3: 0x0001,  # aead: AES-128-GCM
                },
            },
        )
        r.apply(recipient_key=rpk)
        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            recipients=[r],
        )

        # print(encoded.hex())

        # The recipient side:
        rsk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        recipient = COSE.new()
        assert b"This is the content." == recipient.decode(encoded, rsk)

    def test_cose_usage_examples_cose_encrypt_hpke_with_1st_layer_hpke(self):

        # The sender side:
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        r = Recipient.new(
            protected={
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                    2: 0x0001,  # kdf: HKDF-SHA256
                    3: 0x0001,  # aead: AES-128-GCM
                },
            },
        )
        r.apply(recipient_key=rpk)
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                protected={
                    1: -1,  # alg: "HPKE"
                },
                unprotected={
                    4: b"xx",  # kid: "xx"
                    -4: {  # HPKE sender information
                        1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                        2: 0x0001,  # kdf: HKDF-SHA256
                        3: 0x0001,  # aead: AES-128-GCM
                    },
                },
                recipients=[r],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "alg for the first layer should not be HPKE." in str(err.value)

    def test_cose_usage_examples_cose_encrypt_hpke_with_nonce(self):

        # The sender side:
        rpk = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        r = Recipient.new(
            protected={
                1: -1,  # alg: "HPKE"
            },
            unprotected={
                4: b"01",  # kid: "01"
                -4: {  # HPKE sender information
                    1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                    2: 0x0001,  # kdf: HKDF-SHA256
                    3: 0x0001,  # aead: AES-128-GCM
                },
            },
        )
        r.apply(recipient_key=rpk)
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                protected={
                    1: -1,  # alg: "HPKE"
                },
                unprotected={
                    4: b"xx",  # kid: "xx"
                    -4: {  # HPKE sender information
                        1: 0x0010,  # kem: DHKEM(P-256, HKDF-SHA256)
                        2: 0x0001,  # kdf: HKDF-SHA256
                        3: 0x0001,  # aead: AES-128-GCM
                    },
                },
                recipients=[r],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "alg for the first layer should not be HPKE." in str(err.value)

    def test_cose_usage_examples_cose_encrypt_direct_hkdf_sha_256(self):

        shared_material = token_bytes(32)
        shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "direct+HKDF-SHA-256",
                "salt": "aabbccddeeffgghh",
            },
        )
        enc_key = r.apply(shared_key, context={"alg": "A256GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, shared_key, context={"alg": "A256GCM"})

    def test_cose_usage_examples_cose_encrypt_aes_key_wrap_a128kw(self):
        # A key to wrap
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
            },
        )
        r.apply(enc_key)
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(b"Hello world!", key=enc_key, recipients=[r])

        # The recipient side:
        recipient = COSE.new()
        shared_key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        assert b"Hello world!" == recipient.decode(encoded, shared_key)

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_p256(self):

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "P-256",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        enc_key = r.apply(recipient_key=pub_key, context={"alg": "A128GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_x25519(self):

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "X25519",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
            }
        )
        enc_key = r.apply(recipient_key=pub_key, context={"alg": "A128GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X25519",
                "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
                "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_x448(self):

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "X448",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X448",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
            }
        )
        enc_key = r.apply(recipient_key=pub_key, context={"alg": "A128GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "OKP",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "X448",
                "x": "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
                "d": "rJJRG3nshyCtd9CgXld8aNaB9YXKR0UOi7zj7hApg9YH4XdBO0G8NcAFNz_uPH2GnCZVcSDgV5c",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_usage_examples_cose_encrypt_ecdh_ss_a128kw(self):

        # The sender side:
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
        nonce = enc_key.generate_nonce()
        r = Recipient.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
                "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
                "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
            }
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        r.apply(enc_key, recipient_key=pub_key, context={"alg": "A128GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            nonce=nonce,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_usage_examples_cose_signature1(self):

        # The sender side:
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode_and_sign(b"Hello world!", priv_key)

        # The recipient side:
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, pub_key)

        # variation
        sender = COSE.new()
        encoded2 = sender.encode_and_sign(
            b"Hello world!",
            priv_key,
            protected={"alg": "ES256"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == recipient.decode(encoded2, pub_key)

        encoded3 = sender.encode_and_sign(
            b"Hello world!",
            priv_key,
            protected={1: -7},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == recipient.decode(encoded3, pub_key)

    def test_cose_usage_examples_cose_encrypt_ecdh_aes_key_wrap(self):

        enc_key = COSEKey.from_symmetric_key(alg="A128GCM")

        # The sender side:
        r = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+A128KW",
                "crv": "P-256",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+A128KW",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        r.apply(enc_key, recipient_key=pub_key, context={"alg": "A128GCM"})
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+A128KW",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "A128GCM"})

    def test_cose_usage_examples_cose_signature(self):

        # The sender side:
        signer = Signer.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            },
        )
        sender = COSE.new()
        encoded = sender.encode_and_sign(b"Hello world!", signers=[signer])

        # The recipient side:
        recipient = COSE.new()
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        assert b"Hello world!" == recipient.decode(encoded, pub_key)

        # variation
        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected={"alg": "ES256"},
            unprotected={"kid": "01"},
        )
        encoded2 = sender.encode_and_sign(b"Hello world!", signers=[signer])
        assert b"Hello world!" == recipient.decode(encoded2, pub_key)

        signer = Signer.new(
            cose_key=COSEKey.from_jwk(
                {
                    "kty": "EC",
                    "kid": "01",
                    "crv": "P-256",
                    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
                }
            ),
            protected={1: -7},
            unprotected={4: b"01"},
        )
        encoded3 = sender.encode_and_sign(b"Hello world!", signers=[signer])
        assert b"Hello world!" == recipient.decode(encoded3, pub_key)
