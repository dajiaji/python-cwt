from cwt import COSE, COSEKey, Recipient, Signer


class TestCOSESample:
    """
    Tests for samples on COSE Usage Examples.
    """

    def test_cose_usage_examples_cose_mac0(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")

        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

        ctx = COSE.new()
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

    def test_cose_usage_examples_cose_mac_direct(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
        recipient = Recipient.from_jwk({"alg": "direct", "kid": "01"})

        ctx = COSE.new()
        encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])
        assert b"Hello world!" == ctx.decode(encoded, mac_key)

        recipient2 = Recipient.new(unprotected={"alg": "direct", "kid": "01"})
        encoded2 = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient2])
        assert b"Hello world!" == ctx.decode(encoded2, mac_key)

        recipient3 = Recipient.new(unprotected={1: -6, 4: b"01"})
        encoded3 = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient3])
        assert b"Hello world!" == ctx.decode(encoded3, mac_key)

        assert encoded == encoded2 == encoded3

    def test_cose_usage_examples_cose_mac_aes_key_wrap(self):
        mac_key = COSEKey.from_symmetric_key(alg="HS512")
        recipient = Recipient.from_jwk(
            {
                "alg": "A128KW",
                "kid": "our-secret",
                "k": "hJtXIZ2uSN5kbQfbtTNWbg",
            },
        )
        recipient.wrap_key(mac_key.key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_mac(
            b"Hello world!", key=mac_key, recipients=[recipient]
        )
        assert b"Hello world!" == ctx.decode(encoded, recipient)

    def test_cose_usage_examples_cose_encrypt0(self):
        enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
        nonce = enc_key.generate_nonce()

        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key, nonce=nonce)
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

        ctx = COSE.new()
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
        recipient = Recipient.from_jwk({"alg": "direct", "kid": "01"})

        ctx = COSE.new()
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            enc_key,
            nonce=nonce,
            recipients=[recipient],
        )
        assert b"Hello world!" == ctx.decode(encoded, enc_key)

        recipient = Recipient.new(unprotected={"alg": "direct", "kid": "01"})
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

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_p256(self):

        recipient = Recipient.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "crv": "P-256",
            },
        )
        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        enc_key = recipient.derive_key({"alg": "A128GCM"}, public_key=pub_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[recipient],
        )
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
        assert b"Hello world!" == ctx.decode(
            encoded, priv_key, context={"alg": "A128GCM"}
        )

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_x25519(self):

        recipient = Recipient.from_jwk(
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
        enc_key = recipient.derive_key({"alg": "A128GCM"}, public_key=pub_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[recipient],
        )
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
        assert b"Hello world!" == ctx.decode(
            encoded, priv_key, context={"alg": "A128GCM"}
        )

    def test_cose_usage_examples_cose_encrypt_ecdh_direct_hkdf_x448(self):

        recipient = Recipient.from_jwk(
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
        enc_key = recipient.derive_key({"alg": "A128GCM"}, public_key=pub_key)
        ctx = COSE.new(alg_auto_inclusion=True)
        encoded = ctx.encode_and_encrypt(
            b"Hello world!",
            key=enc_key,
            recipients=[recipient],
        )
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
        assert b"Hello world!" == ctx.decode(
            encoded, priv_key, context={"alg": "A128GCM"}
        )

    def test_cose_usage_examples_cose_signature1(self):

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
        ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        encoded = ctx.encode_and_sign(b"Hello world!", priv_key)

        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        assert b"Hello world!" == ctx.decode(encoded, pub_key)

        ctx = COSE.new()
        encoded2 = ctx.encode_and_sign(
            b"Hello world!",
            priv_key,
            protected={"alg": "ES256"},
            unprotected={"kid": "01"},
        )
        assert b"Hello world!" == ctx.decode(encoded2, pub_key)

        encoded3 = ctx.encode_and_sign(
            b"Hello world!",
            priv_key,
            protected={1: -7},
            unprotected={4: b"01"},
        )
        assert b"Hello world!" == ctx.decode(encoded3, pub_key)

    def test_cose_usage_examples_cose_signature(self):

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
        ctx = COSE.new()
        encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            }
        )
        assert b"Hello world!" == ctx.decode(encoded, pub_key)

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
        encoded2 = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        assert b"Hello world!" == ctx.decode(encoded2, pub_key)

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
        encoded3 = ctx.encode_and_sign(b"Hello world!", signers=[signer])
        assert b"Hello world!" == ctx.decode(encoded3, pub_key)
