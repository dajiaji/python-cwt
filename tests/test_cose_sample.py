from cwt import COSE, COSEKey, Recipient


class TestCOSESample:
    """
    Tests for samples on COSE Usage Examples.
    """

    def test_cose_usage_examples_cose_mac0(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")

        ctx = COSE(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

        ctx = COSE()
        encoded2 = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={"alg": "HS256"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == ctx.decode(encoded2, mac_key)

        encoded3 = ctx.encode_and_mac(
            b"Hello world!",
            mac_key,
            protected={1: 5},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == ctx.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
        recipient = Recipient.from_json({"alg": "direct", "kid": "01"})

        ctx = COSE()
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

        recipient2 = Recipient.from_dict(unprotected={"alg": "direct", "kid": "01"})
        encoded2 = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient2])
        assert b"Hello world!" == ctx.decode(encoded2, mac_key)

        recipient3 = Recipient.from_dict(unprotected={1: -6, 4: b"01"})
        encoded3 = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient3])
        assert b"Hello world!" == ctx.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_encrypt0(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        nonce = enc_key.generate_nonce()

        ctx = COSE(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, nonce=nonce)
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

        ctx = COSE()
        encoded2 = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            protected={"alg": "ChaCha20/Poly1305"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == ctx.decode(encoded2, enc_key)

        encoded3 = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            protected={1: 24},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == ctx.decode(encoded3, enc_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_encrypt(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        nonce = enc_key.generate_nonce()
        recipient = Recipient.from_json({"alg": "direct", "kid": "01"})

        ctx = COSE()
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[recipient],
        )
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

        recipient = Recipient.from_dict(unprotected={"alg": "direct", "kid": "01"})
        encoded2 = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[recipient],
        )
        assert b"Hello world!" == ctx.decode(encoded2, enc_key)

        encoded3 = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[recipient],
        )
        assert b"Hello world!" == ctx.decode(encoded3, enc_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_signature1(self):

        sig_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
            }
        )
        ctx = COSE(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_sign(b"Hello world!", sig_key)
        assert b"Hello world!" == ctx.decode(encoded, sig_key)

        ctx = COSE()
        encoded2 = ctx.encode_and_sign(
            b"Hello world!",
            sig_key,
            protected={"alg": "ES256"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == ctx.decode(encoded2, sig_key)

        encoded3 = ctx.encode_and_sign(
            b"Hello world!",
            sig_key,
            protected={1: -7},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == ctx.decode(encoded3, sig_key)
