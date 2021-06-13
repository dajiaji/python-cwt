===================
COSE Usage Examples
===================

The following is a simple sample code for command line console.

.. code-block:: pycon

    >>> from cwt import COSE, COSEKey
    >>> ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    >>> mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    >>> encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
    >>> encoded.hex()
    'd18443a10105a1044230314c48656c6c6f20776f726c642158205d0b144add282ccaac32a02e0d5eec76928ccadf3623271eb48e9464e2ee03b2'
    >>> ctx.decode(encoded, mac_key)
    b'Hello world!'

This page shows various examples to use COSE API in this library. Specific examples are as follows:

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
    decoded = ctx.decode(encoded, mac_key)

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
    decoded = ctx.decode(encoded, mac_key)

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
    decoded = ctx.decode(encoded, mac_key)

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
    decoded = ctx.decode(encoded, mac_key)

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
    decoded = ctx.decode(encoded, mac_key)

.. code-block:: python

    from cwt import COSE, COSEKey, Recipient

    # The sender side:
    # new() can accept following raw COSE header parameters.
    recipient = Recipient.new(unprotected={1: 7, 4: b"01"})
    mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
    ctx = COSE.new()
    encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[recipient])

    # The recipient side:
    decoded = ctx.decode(encoded, mac_key)

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
    decoded = ctx.decode(encoded, recipient)

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
    decoded = ctx.decode(encoded, enc_key)

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
    decoded = ctx.decode(encoded, enc_key)

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
    decoded = ctx.decode(encoded, enc_key)

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
    decoded = ctx.decode(encoded, enc_key)

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
    decoded = ctx.decode(encoded, pub_key)

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
    decoded = ctx.decode(encoded, sig_key)


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
    decoded = ctx.decode(encoded, sig_key)

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
    decoded = ctx.decode(encoded, pub_key)

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
    decoded = ctx.decode(encoded, pub_key)


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
    decoded = ctx.decode(encoded, pub_key)

.. _`Supported COSE Algorithms`: ./algorithms.html
