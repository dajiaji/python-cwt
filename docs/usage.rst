Usage Examples
==============

MACed CWT
---------

Create a MACed CWT, verify and decode it as follows:

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

Create a Signed CWT, verify and decode it with the key pair as follows:

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

Create an encrypted CWT with ``ChaCha20/Poly1305`` (ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag),
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

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

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

CWT with PoP key
----------------

Create a CWT which has a PoP key as follows:

.. code-block:: python

    # An issuer prepares a signing key for CWT in advance.
    with open(key_path("private_key_ed25519.pem")) as key_file:
        private_key = cose_key.from_pem(key_file.read())

    # Prepares the presenter's PoP key.
    with open(key_path("public_key_es256.pem")) as key_file:
        pop_key = cose_key.from_pem(key_file.read())

    # Sets the PoP key to a CWT for the presenter.
    token = cwt.encode(
        {
            1: "https://as.example",  # iss
            2: "dajiaji",  # sub
            7: b"123",  # cti
            8: {  # cnf
                1: pop_key.to_dict(),
            },
        },
        private_key,
    )

On the CWT recipient side, extracts the PoP key and uses it as follows:

.. code-block:: python

    # A CWT recipient prepares the public key of the issuer in advance.
    with open(key_path("public_key_ed25519.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Verifies and decodes the CWT received.
    decoded = cwt.decode(token, public_key)

    # Extracts the PoP key from the CWT.
    extracted_pop_key = cose_key.from_dict(decoded[8][1])  #  8:cnf, 1:COSE_Key

    # Then, verifies the message sent by the presenter
    # with the signature which is also sent by the presenter as follows:
    #    extracted_pop_key.verify(message, signature)

In case of another PoP confirmation method ``Encrypted_COSE_Key``:

.. code-block:: python

    with open(key_path("private_key_ed25519.pem")) as key_file:
        private_key = cose_key.from_pem(key_file.read())

    enc_key = cose_key.from_symmetric_key(
        "a-client-secret-of-cwt-recipient",  # Just 32 bytes!
        alg="ChaCha20/Poly1305",
    )
    pop_key = cose_key.from_symmetric_key(
        "a-client-secret-of-cwt-presenter",
        alg="HMAC 256/256",
    )

    token = cwt.encode(
        {
            1: "https://as.example",  # iss
            2: "dajiaji",  # sub
            7: b"124",  # cti
            8: {  # cnf
                2: cose_key.to_encrypted_cose_key(pop_key, enc_key),
            },
        },
        private_key,
    )

    with open(key_path("public_key_ed25519.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())
    decoded = cwt.decode(token, public_key)
    extracted_pop_key = cose_key.from_encrypted_cose_key(decoded[8][2], enc_key)
    # extracted_pop_key.verify(message, signature)

In case of another PoP confirmation method ``kid``:

.. code-block:: python

    with open(key_path("private_key_ed25519.pem")) as key_file:
        private_key = cose_key.from_pem(key_file.read())

    token = cwt.encode(
        {
            1: "https://as.example",  # iss
            2: "dajiaji",  # sub
            7: b"124",  # cti
            8: {  # cnf
                3: b"pop-key-id-of-cwt-presenter",
            },
        },
        private_key,
    )

    with open(key_path("public_key_ed25519.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())
    decoded = cwt.decode(token, public_key)
    # decoded[8][3] is kid.

.. _`Supported COSE Algorithms`: ./algorithms.html
