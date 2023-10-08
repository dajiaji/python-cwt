from secrets import token_bytes

import pytest

from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, Recipient, Signer


class TestCOSESample:
    """
    Tests for samples on COSE Usage Examples.
    """

    def test_cose_usage_examples_cose_mac0(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

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
            protected={COSEHeaders.ALG: COSEAlgs.HS256},
            unprotected={COSEHeaders.KID: b"01"},
        )
        assert b"Hello world!" == recipient.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac_direct(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS512", kid="01")

        # The sender side:
        r = Recipient.new(unprotected={"alg": "direct"})

        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
            # protected={"alg": "HS512"},
            # unprotected={"kid": mac_key.kid},
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, mac_key)

        # variation
        r2 = Recipient.new(unprotected={"alg": "direct"})
        encoded2 = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={"alg": "HS512"},
            unprotected={"kid": mac_key.kid},
            recipients=[r2],
        )
        assert b"Hello world!" == recipient.decode(encoded2, mac_key)

        r3 = Recipient.new(unprotected={COSEHeaders.ALG: COSEAlgs.DIRECT})
        encoded3 = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={COSEHeaders.ALG: COSEAlgs.HS512},
            unprotected={COSEHeaders.KID: mac_key.kid},
            recipients=[r3],
        )
        assert b"Hello world!" == recipient.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac_direct_hkdf_sha_256(self):
        shared_material = token_bytes(32)
        shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

        # The sender side:
        r = Recipient.new(
            unprotected={
                "alg": "direct+HKDF-SHA-256",
                "salt": "aabbccddeeffgghh",
            },
            context={"alg": "HS256"},
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            shared_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, shared_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_mac_aes_key_wrap(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS512")

        # The sender side:
        enc_key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "kid": "01",
                "alg": "A128KW",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
            }
        )
        r = Recipient.new(unprotected={"alg": "A128KW"}, sender_key=enc_key)
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(b"Hello world!", mac_key, recipients=[r])

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, enc_key)

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
        r = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context={"alg": "HS256"},
        )
        sender = COSE.new()
        encoded = sender.encode_and_mac(
            b"Hello world!",
            protected={"alg": "HS256"},
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

    def test_cose_usage_examples_cose_mac_ecdh_ss_a128kw(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256")

        # The sender side:
        priv_key = COSEKey.from_jwk(
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
        r = Recipient.new(
            unprotected={"alg": "ECDH-SS+A128KW"},
            sender_key=priv_key,
            recipient_key=pub_key,
            context={"alg": "HS256"},
        )
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

    def test_cose_usage_examples_cose_mac_ecdh_aes_key_wrap(self):
        mac_key = COSEKey.generate_symmetric_key(alg="HS256")

        # The sender side:
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
        r = Recipient.new(
            unprotected={"alg": "ECDH-ES+A128KW"},
            recipient_key=pub_key,
            context={"alg": "HS256"},
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_mac(
            b"Hello world!",
            mac_key,
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
        assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})

    def test_cose_usage_examples_cose_encrypt0(self):
        enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

        # The sender side:
        nonce = enc_key.generate_nonce()
        sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(b"Hello world!", enc_key, unprotected={5: nonce})

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, enc_key)

        # variation
        sender = COSE.new()
        encoded2 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected={"alg": "ChaCha20/Poly1305"},
            unprotected={"kid": "01", "iv": nonce},
        )
        assert b"Hello world!" == recipient.decode(encoded2, enc_key)

        encoded3 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected={COSEHeaders.ALG: COSEAlgs.CHACHA20_POLY1305},
            unprotected={COSEHeaders.KID: b"01", COSEHeaders.IV: nonce},
        )
        assert b"Hello world!" == recipient.decode(encoded3, enc_key)

        # assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_encrypt0_hpke(self):
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

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            rpk,
            protected={
                COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
            },
            unprotected={
                COSEHeaders.KID: b"01",
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
        enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

        # The sender side:
        nonce = enc_key.generate_nonce()
        r = Recipient.new(unprotected={"alg": "direct"})

        sender = COSE.new()
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected={"alg": "ChaCha20/Poly1305"},
            unprotected={"kid": enc_key.kid, "iv": nonce},
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, enc_key)

        # variation
        r = Recipient.new(unprotected={COSEHeaders.ALG: COSEAlgs.DIRECT})
        encoded2 = sender.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            protected={COSEHeaders.ALG: COSEAlgs.CHACHA20_POLY1305},
            unprotected={COSEHeaders.KID: enc_key.kid, COSEHeaders.IV: nonce},
            recipients=[r],
        )
        assert b"Hello world!" == recipient.decode(encoded2, enc_key)

        assert encoded == encoded2

    def test_cose_usage_examples_cose_encrypt_hpke(self):
        # The sender side:
        enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
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
                COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
            },
            unprotected={
                COSEHeaders.KID: b"01",
            },
            recipient_key=rpk,
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"This is the content.",
            key=enc_key,
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
        # enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
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
                COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
            },
            unprotected={
                COSEHeaders.KID: b"01",
            },
            recipient_key=rpk,
        )
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                protected={
                    COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
                },
                unprotected={
                    COSEHeaders.KID: b"xx",
                },
                recipients=[r],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "key should be set." in str(err.value)

    def test_cose_usage_examples_cose_encrypt_hpke_with_nonce(self):
        # The sender side:
        # enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
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
                COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
            },
            unprotected={
                COSEHeaders.KID: b"01",
            },
            recipient_key=rpk,
        )
        sender = COSE.new()
        with pytest.raises(ValueError) as err:
            sender.encode_and_encrypt(
                b"This is the content.",
                protected={
                    COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
                },
                unprotected={
                    COSEHeaders.KID: b"xx",  # kid: "xx"
                },
                recipients=[r],
            )
            pytest.fail("encode_and_encrypt should fail.")
        assert "key should be set." in str(err.value)

    def test_cose_usage_examples_cose_encrypt_direct_hkdf_sha_256(self):
        shared_material = token_bytes(32)
        shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

        # The sender side:
        r = Recipient.new(
            unprotected={
                "alg": "direct+HKDF-SHA-256",
                "salt": "aabbccddeeffgghh",
            },
            context={"alg": "A256GCM"},
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            shared_key,
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, shared_key, context={"alg": "A256GCM"})

    def test_cose_usage_examples_cose_encrypt_aes_key_wrap_a128kw(self):
        # A key to wrap
        enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305")

        # The sender side:
        wrapping_key = COSEKey.from_jwk(
            {
                "kty": "oct",
                "alg": "A128KW",
                "kid": "01",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
            }
        )
        r = Recipient.new(
            unprotected={"alg": "A128KW"},
            sender_key=wrapping_key,
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(b"Hello world!", key=enc_key, recipients=[r])

        # The recipient side:
        recipient = COSE.new()
        assert b"Hello world!" == recipient.decode(encoded, wrapping_key)

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_p256(self):
        # The sender side:
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        r = Recipient.new(
            unprotected={"alg": "ECDH-ES+HKDF-256"},
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
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

    def test_cose_usage_examples_cose_encrypt_ecdh_ss_a128kw(self):
        # The sender side:
        enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
        nonce = enc_key.generate_nonce()
        r_pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "meriadoc.brandybuck@buckland.example",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        s_priv_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ECDH-SS+A128KW",
                "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
                "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
                "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
            }
        )
        r = Recipient.new(
            unprotected={"alg": "ECDH-SS+A128KW"},
            sender_key=s_priv_key,
            recipient_key=r_pub_key,
            context={"alg": "A128GCM"},
        )
        sender = COSE.new(alg_auto_inclusion=True)
        encoded = sender.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            unprotected={5: nonce},
            recipients=[r],
        )

        # The recipient side:
        recipient = COSE.new()
        r_priv_key = COSEKey.from_jwk(
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
        assert b"Hello world!" == recipient.decode(encoded, r_priv_key, context={"alg": "A128GCM"})

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
            protected={COSEHeaders.ALG: COSEAlgs.ES256},
            unprotected={COSEHeaders.KID: b"01"},
        )
        assert b"Hello world!" == recipient.decode(encoded3, pub_key)

    def test_cose_usage_examples_cose_encrypt_ecdh_aes_key_wrap(self):
        enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")

        # The sender side:
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
        r = Recipient.new(
            unprotected={"alg": "ECDH-ES+A128KW"},
            recipient_key=pub_key,
            context={"alg": "A128GCM"},
        )
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
            protected={COSEHeaders.ALG: COSEAlgs.ES256},
            unprotected={COSEHeaders.KID: b"01"},
        )
        encoded3 = sender.encode_and_sign(b"Hello world!", signers=[signer])
        assert b"Hello world!" == recipient.decode(encoded3, pub_key)
