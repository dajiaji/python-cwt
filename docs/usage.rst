Usage Examples
==============

The following is the simplest sample code.

.. code-block:: pycon

    >>> import cwt
    >>> from cwt import claims, cose_key
    >>> key = cose_key.from_symmetric_key(alg="HS256")
    >>> token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
    >>> token.hex()
    'd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a69'
    '0743313233041a609097b7051a609089a7061a609089a758201fad9b0a76803194bd11ca9b9b3c'
    'bbf1028005e15321665a768994f38c7127f7'
    >>> decoded = cwt.decode(token, key)
    >>> decoded
    {1: 'coaps://as.example', 2: 'dajiaji', 7: b'123',
     4: 1620088759, 5: 1620085159, 6: 1620085159}
    >>> readable = claims.from_dict(decoded)
    >>> readable.iss
    'coaps://as.example'
    >>> readable.sub
    'dajiaji'
    >>> readable.exp
    1620088759

This page shows various examples to use this library. Specific examples are as follows:

.. contents::
   :local:

MACed CWT
---------

Create a MACed CWT, verify and decode it as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    try:
        key = cose_key.from_symmetric_key(alg="HS256")
        token = cwt.encode(
            {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
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

    key = cose_key.from_symmetric_key(alg="HMAC 256/256")  # Same as "HS256"
    token = cwt.encode({1: "coaps://as.example", 2: "dajiaji", 7: b"123"}, key)
    decoded = cwt.decode(token, key)

Algorithms other than ``HS256`` are listed in `Supported COSE Algorithms`_ .

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

    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())


    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    decoded = cwt.decode(token, public_key)

JWKs can also be used instead of the PEM-formatted keys as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key

    private_key = cose_key.from_jwk(
        {
            "kty": "OKP",
            "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "01",
            "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            "alg": "EdDSA",
        }
    )
    public_key = cose_key.from_jwk(
        {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "01",
            "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        }
    )

    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )
    decoded = cwt.decode(token, public_key)

Algorithms other than ``Ed25519`` are also supported. The following is an example of ``ES256``:

.. code-block:: console

    $ openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
    $ openssl ec -in private_key.pem -pubout -out public_key.pem

.. code-block:: python

    import cwt
    from cwt import cose_key

    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

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
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
    )
    decoded = cwt.decode(token, enc_key)

Algorithms other than ``ChaCha20/Poly1305`` are also supported. The following is an example of
``AES-CCM-16-64-256``:

.. code-block:: python

    import cwt
    from cwt import cose_key

    enc_key = cose_key.from_symmetric_key(alg="AES-CCM-16-64-256")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
    )
    decoded = cwt.decode(token, enc_key)

Other supported algorithms are listed in `Supported COSE Algorithms`_.

Nested CWT
----------

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

.. code-block:: python

    import cwt
    from cwt import cose_key

    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Creates a CWT with ES256 signing.
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # Encrypts the signed CWT.
    enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
    nested = cwt.encode(token, enc_key)

    # Decrypts and verifies the nested CWT.
    decoded = cwt.decode(nested, [enc_key, public_key])

CWT with PoP key
----------------

Create a CWT which has a PoP key as follows:

On the issuer side:

.. code-block:: python

    import cwt
    from cwt import cose_key

    # Prepares a signing key for CWT in advance.
    with open(key_path("private_key_of_issuer.pem")) as key_file:
        private_key = cose_key.from_pem(key_file.read())

    # Sets the PoP key to a CWT for the presenter.
    token = cwt.encode(
        {
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": "123",
            "cnf": {
                "jwk": {  # Provided by the CWT presenter.
                    "kty": "OKP",
                    "use": "sig",
                    "crv": "Ed25519",
                    "kid": "01",
                    "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
                    "alg": "EdDSA",
                },
            },
        },
        private_key,
    )

    # Issues the token to the presenter.

On the CWT presenter side:

.. code-block:: python

    import cwt
    from cwt import cose_key

    # Prepares a private PoP key in advance.
    with open("./private_pop_key.pem") as key_file:
        pop_key_private = cose_key.from_pem(key_file.read())

    # Receives a message (e.g., nonce)  from the recipient.
    msg = b"could-you-sign-this-message?"  # Provided by recipient.

    # Signs the message with the private PoP key.
    sig = pop_key_private.sign(msg)

    # Sends the msg and the sig with the CWT to the recipient.

On the CWT recipient side:

.. code-block:: python

    import cwt
    from cwt import claims, cose_key

    # Prepares the public key of the issuer in advance.
    with open(key_path("public_key_of_issuer.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Verifies and decodes the CWT received from the presenter.
    raw = cwt.decode(token, public_key)
    decoded = claims.from_dict(raw)

    # Extracts the PoP key from the CWT.
    extracted_pop_key = cose_key.from_dict(decoded.cnf)  #  = raw[8][1]

    # Then, verifies the message sent by the presenter
    # with the signature which is also sent by the presenter as follows:
    extracted_pop_key.verify(msg, sig)

In case of another PoP confirmation method ``Encrypted_COSE_Key``:

.. code-block:: python

    import cwt
    from cwt import claims, cose_key

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
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": "123",
            "cnf": {
                # 'eck'(Encrypted Cose Key) is a keyword defined by this library.
                "eck": cose_key.to_encrypted_cose_key(pop_key, enc_key),
            },
        },
        private_key,
    )

    with open(key_path("public_key_ed25519.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())
    raw = cwt.decode(token, public_key)
    decoded = claims.from_dict(raw)
    extracted_pop_key = cose_key.from_encrypted_cose_key(decoded.cnf, enc_key)
    # extracted_pop_key.verify(message, signature)

In case of another PoP confirmation method ``kid``:

.. code-block:: python

    import cwt
    from cwt import claims, cose_key

    with open(key_path("private_key_ed25519.pem")) as key_file:
        private_key = cose_key.from_pem(key_file.read())

    token = cwt.encode(
        {
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": "123",
            "cnf": {
                "kid": "pop-key-id-of-cwt-presenter",
            },
        },
        private_key,
    )

    with open(key_path("public_key_ed25519.pem")) as key_file:
        public_key = cose_key.from_pem(key_file.read())
    raw = cwt.decode(token, public_key)
    decoded = claims.from_dict(raw)
    # decoded.cnf(=raw[8][3]) is kid.

.. _`Supported COSE Algorithms`: ./algorithms.html
