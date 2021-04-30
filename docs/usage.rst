Usage Examples
==============

MACed CWT
---------

Encode a MACed CWT, verify and decode it as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    try:
        key = cose_key.from_symmetric_key(alg="HMAC 256/256")
        token = cwt.encode(
            {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"},
            key,
        )
        decoded = cwt.decode(token, key)
    except Exception as err:
        # All the other examples in this document omit error handling but this CWT library
        # can throw following errors:
        #   ValueError: Invalid arguments.
        #   EncodeError: Failed to encode.
        #   VerifyError: Failed to verify.
        #   DecodeError: Failed to decode.
        print(err)


CBOR-like structure (Dict[int, Any]) can also be used as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    key = cose_key.from_symmetric_key(alg="HMAC 256/256")
    token = cwt.encode({1: "https://as.example", 2: "dajiaji", 7: b"123"}, key)
    decoded = cwt.decode(token, key)

Algorithms other than ``HMAC 256/256`` are listed in `Supported COSE Algorithms`_ .

Signed CWT
----------

Create an ``Ed25519`` (Ed25519 for use w/ EdDSA only) key pair:

.. code-block:: console

    $ openssl genpkey -algorithm ed25519 -out private_key.pem
    $ openssl pkey -in private_key.pem -pubout -out public_key.pem

Encode a Signed CWT, verify and decode it with the key pair as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    # Load PEM-formatted keys as COSE keys.
    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())


    # Encode with Ed25519 signing.
    token = cwt.encode(
        {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # Verify and decode.
    decoded = cwt.decode(token, public_key)

Algorithms other than ``Ed25519`` are also supported. The following is an example of ``ES256``:

.. code-block:: console

    $ openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
    $ openssl ec -in private_key.pem -pubout -out public_key.pem

.. code-block:: python

    import cwt
    from cwt import cose_key

    # Load PEM-formatted keys as COSE keys.
    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Encode with ES256 signing.
    token = cwt.encode(
        {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # Verify and decode.
    decoded = cwt.decode(token, public_key)

Other supported algorithms are listed in `Supported COSE Algorithms`_.

Encrypted CWT
-------------

Encode an encrypted CWT with ``ChaCha20/Poly1305`` (ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag),
and decrypt it as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
    token = cwt.encode(
        {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
    )
    decoded = cwt.decode(token, enc_key)

Algorithms other than ``ChaCha20/Poly1305`` are also supported. The following is an example of
``AES-CCM-16-64-256``:

.. code-block:: python

    import cwt
    from cwt import cose_key

    enc_key = cose_key.from_symmetric_key(alg="AES-CCM-16-64-256")
    token = cwt.encode(
        {"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
    )
    decoded = cwt.decode(token, enc_key)

Other supported algorithms are listed in `Supported COSE Algorithms`_.

Nested CWT
----------

Encode a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

.. code-block:: python

    import cwt
    from cwt import cose_key

    # Load PEM-formatted keys as COSE keys.
    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Encode with ES256 signing.
    token = cwt.encode(
        {"iss": "https://as.example", "sub": "dajiaji", "cti": "124"}, private_key
    )

    # Encrypt the signed CWT.
    enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
    nested = cwt.encode(token, enc_key)

    # Decrypt and verify the nested CWT.
    decoded = cwt.decode(nested, [enc_key, public_key])

.. _`Supported COSE Algorithms`: ./algorithms.html
