Usage Examples
==============

MACed CWT
---------

Create a MACed CWT, verify and decode it as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key, claims

    key = cose_key.from_symmetric_key(
        "mysecretpassword"
    )  # Default algorithm is "HMAC 256/256"
    encoded = cwt.encode_and_mac(
        claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
        key,
    )
    decoded = cwt.decode(encoded, key)


CBOR-like structure (Dict[int, Any]) can also be used as follows:

.. code-block:: python

    import cwt

    key = cwt.cose_key.from_symmetric_key("mysecretpassword")
    encoded = cwt.encode_and_mac(
        {1: "https://as.example", 2: "dajiaji", 7: b"123"},
        key,
    )
    decoded = cwt.decode(encoded, key)

Signed CWT
----------

Create an `ES256` (ECDSA with SHA-256) key pair:

.. code-block:: console

    $ openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
    $ openssl ec -in private_key.pem -pubout -out public_key.pem


Create a Signed CWT, verify and decode it with the key pair as follows:

.. code-block:: python

    import cwt
    from cwt import cose_key, claims

    # Load PEM-formatted keys as COSE keys.
    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Encode with ES256 signing.
    encoded = cwt.encode_and_sign(
        claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
        private_key,
    )

    # Verify and decode.
    decoded = cwt.decode(encoded, public_key)

Algorithms other than `ES256` are also supported. The following is an example of `Ed25519`:

.. code-block:: console

    $ openssl genpkey -algorithm ed25519 -out private_key.pem
    $ openssl pkey -in private_key.pem -pubout -out public_key.pem

.. code-block:: python

    import cwt
    from cwt import cose_key, claims

    # Load PEM-formatted keys as COSE keys.
    with open("./private_key.pem") as key_file:
        private_key = cose_key.from_pem(key_file.read())
    with open("./public_key.pem") as key_file:
        public_key = cose_key.from_pem(key_file.read())

    # Encode with Ed25519 signing.
    encoded = cwt.encode_and_encrypt(
        claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
        private_key,
    )

    # Verify and decode.
    decoded = cwt.decode(encoded, public_key)

Encrypted CWT
-------------

Create an encrypted CWT with `AES-CCM-16-64-256` (AES-CCM mode using 128-bit symmetric key),
and decrypt it as follows:

.. code-block:: python

    from secrets import token_bytes
    import cwt
    from cwt import cose_key, claims

    nonce = token_bytes(13)
    mysecret = token_bytes(32)
    enc_key = cose_key.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256")
    encoded = cwt.encode_and_encrypt(
        claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
        enc_key,
        nonce=nonce,
    )
    decoded = cwt.decode(encoded, enc_key)

Nested CWT
----------

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

.. code-block:: python

   from secrets import token_bytes
   import cwt
   from cwt import cose_key, claims

   # Load PEM-formatted keys as COSE keys.
   with open("./private_key.pem") as key_file:
       private_key = cose_key.from_pem(key_file.read())
   with open("./public_key.pem") as key_file:
       public_key = cose_key.from_pem(key_file.read())

   # Encode with ES256 signing.
   encoded = cwt.encode_and_sign(
       claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
       private_key,
   )

   # Encrypt the signed CWT.
   nonce = token_bytes(13)
   mysecret = token_bytes(32)
   enc_key = cose_key.from_symmetric_key(mysecret, alg="AES-CCM-16-64-256")
   nested = cwt.encode_and_encrypt(encoded, enc_key, nonce=nonce)

   # Decrypt and verify the nested CWT.
   decoded = cwt.decode(nested, [enc_key, public_key])
