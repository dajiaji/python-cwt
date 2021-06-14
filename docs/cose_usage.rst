===================
COSE Usage Examples
===================

The following is a simple sample code using COSE API:

.. code-block:: pycon

    >>> from cwt import COSE, COSEKey
    >>> ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    >>> mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    >>> encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
    >>> encoded.hex()
    'd18443a10105a1044230314c48656c6c6f20776f726c642158205d0b144add282ccaac32a02e0d5eec76928ccadf3623271eb48e9464e2ee03b2'
    >>> ctx.decode(encoded, mac_key)
    b'Hello world!'

This page shows various examples to use COSE API in this library.

.. contents::
   :local:

COSE MAC0
=========

Create a COSE MAC0 message, verify and decode it as follows:

.. code-block:: python

    from cwt import COSE, COSEKey

    mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

Algorithms other than ``HS256`` are listed in `Supported COSE Algorithms`_ .

Following two samples are other ways of writing the above example:

.. code-block:: python

    from cwt import COSE, COSEKey

    mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(
        b"Hello world!",
        mac_key,
        protected={"alg": "HS256"},
        unprotected={"kid": "01"},
    )
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

.. code-block:: python

    from cwt import COSE, COSEKey

    mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(
        b"Hello world!",
        mac_key,
        protected={1: 5},
        unprotected={4: b"01"},
    )
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

COSE MAC
========

Direct Key Distribution
-----------------------

The direct key distribution shares a MAC key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE MAC message, verify and decode it with the direct
key distribution method.

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender makes a COSE MAC message as follows:
    recipient = Recipient.from_jwk({"alg": "direct", "kid": "01"})
    mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])

    # The recipient has the same MAC key and can verify and decode it:
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

Following samples are other ways of writing the above sample:

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
    # In contrast to from_jwk(), new() is low-level constructor.
    recipient = Recipient.new(unprotected={"alg": "direct", "kid": "01"})
    mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
    # new() can accept following raw COSE header parameters.
    recipient = Recipient.new(unprotected={1: 7, 4: b"01"})
    mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, mac_key)

AES Key Wrap
------------

The AES key wrap algorithm can be used to wrap a MAC key as follows:

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
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
    encoded = ctx.encode_and_mac(b"Hello world!", key=mac_key, recipients=[recipient])

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, recipient)

COSE Encrypt0
=============

Create a COSE Encrypt0 message, verify and decode it as follows:

.. code-block:: python

    from cwt import COSE, COSEKey

    # The sender side:
    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
    ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key)

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, enc_key)

Algorithms other than ``ChaCha20/Poly1305`` are listed in `Supported COSE Algorithms`_ .

Following two samples are other ways of writing the above example:

.. code-block:: python

    from cwt import COSE, COSEKey

    # The sender side:
    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_encrypt(
        b"Hello world!",
        enc_key,
        nonce=nonce,
        protected={"alg": "ChaCha20/Poly1305"},
        unprotected={"kid": "01"},
    )

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, enc_key)

.. code-block:: python

    from cwt import COSE, COSEKey

    # The sender side:
    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_encrypt(
        b"Hello world!",
        enc_key,
        nonce=nonce,
        protected={1: 24},
        unprotected={4: b"01"},
    )

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, enc_key)

COSE Encrypt
============

Direct Key Distribution
-----------------------

The direct key distribution shares an encryption key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE Encrypt message, verify and decode it with the direct
key distribution method.

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
    recipient = Recipient.from_jwk({"alg": "direct", "kid": "01"})
    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_encrypt(
        b"Hello world!",
        enc_key,
        recipients=[recipient],
    )

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, enc_key)

Direct Key Agreement
--------------------

The direct key agreement methods can be used to create a shared secret. A KDF (Key Distribution Function) is then
applied the shared secret to derive a key to be used to protect the data.
The follwing example shows a simple way to make a COSE Encrypt message, verify and decode it with the direct key
agreement methods (``ECDH-ES+HKDF-256`` with various curves).

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
    recipient = Recipient.from_jwk(
        {
            "kty": "EC",
            "alg": "ECDH-ES+HKDF-256",
            "crv": "P-256",
        },
    )
    # The following key is provided by the recipient in advance.
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
    # The enc_key will be derived in decode() with priv_key and
    # the sender's public key which is conveyed as the recipient
    # information structure in the COSE Encrypt message (encoded).
    assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

You can use other curves (``P-384``, ``P-521``, ``X25519``, ``X448``) instead of ``P-256``:

In case of ``X25519``:

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
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

    # The recipient side:
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
    assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})

In case of ``X448``:

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

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
    assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})


COSE Signature1
===============

Create a COSE Signature1 message, verify and decode it as follows:

.. code-block:: python

    from cwt import COSE, COSEKey

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
    ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    encoded = ctx.encode_and_sign(b"Hello world!", priv_key)

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
    assert b"Hello world!" == ctx.decode(encoded, pub_key)

Following two samples are other ways of writing the above example:

.. code-block:: python

    from cwt import COSE, COSEKey

    # The sender side:
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
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(
        b"Hello world!",
        sig_key,
        protected={"alg": "ES256"},
        unprotected={"kid": "01"},
    )

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, sig_key)


.. code-block:: python

    from cwt import COSE, COSEKey

    # The sender side:
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
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(
        b"Hello world!",
        sig_key,
        protected={1: -7},
        unprotected={4: b"01"},
    )

    # The recipient side:
    assert b"Hello world!" == ctx.decode(encoded, sig_key)

COSE Signature
==============

Create a COSE Signature message, verify and decode it as follows:

.. code-block:: python

    from cwt import COSE, COSEKey, Signer

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
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

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
    assert b"Hello world!" == ctx.decode(encoded, pub_key)

Following two samples are other ways of writing the above example:

.. code-block:: python

    from cwt import COSE, COSEKey, Signer

    # The sender side:
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
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

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
    assert b"Hello world!" == ctx.decode(encoded, pub_key)


.. code-block:: python

    from cwt import COSE, COSEKey, Signer

    # The sender side:
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
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

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
    assert b"Hello world!" == ctx.decode(encoded, pub_key)

.. _`Supported COSE Algorithms`: ./algorithms.html
