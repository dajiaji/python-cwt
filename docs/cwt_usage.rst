CWT Usage Examples
==================

The following is a simple sample code using CWT API:

.. code-block:: pycon

    >>> import cwt
    >>> from cwt import Claims, COSEKey
    >>> key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    >>> token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
    >>> token.hex()
    'd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a609097b7051a609089a7061a609089a758201fad9b0a76803194bd11ca9b9b3cbbf1028005e15321665a768994f38c7127f7'
    >>> cwt.decode(token, key)
    {1: 'coaps://as.example', 2: 'dajiaji', 7: b'123', 4: 1620088759, 5: 1620085159, 6: 1620085159}

This page shows various examples to use CWT API in this library.

.. contents::
   :local:

MACed CWT
---------

Create a MACed CWT, verify and decode it as follows:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    try:
        key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
        token = cwt.encode(
            {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
            key,
        )
        decoded = cwt.decode(token, key)

        # If you want to treat the result like a JWT;
        readable = Claims.new(decoded)
        assert readable.iss == "coaps://as.example"
        assert readable.sub == "dajiaji"
        assert readable.cti == "123"
        # readable.exp == 1620088759
        # readable.nbf == 1620085159
        # readable.iat == 1620085159

    except Exception as err:
        # All the other examples in this document omit error handling but this CWT library
        # can throw following errors:
        #   ValueError: Invalid arguments.
        #   EncodeError: Failed to encode.
        #   VerifyError: Failed to verify.
        #   DecodeError: Failed to decode.
        print(err)


A raw CWT structure (Dict[int, Any]) can also be used as follows:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
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
    from cwt import COSEKey

    # The sender side:
    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="01")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # The recipient side:
    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="01")
    decoded = cwt.decode(token, public_key)

JWKs can also be used instead of the PEM-formatted keys as follows:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    # The sender side:
    private_key = COSEKey.from_jwk(
        {
            "kid": "01",
            "kty": "OKP",
            "key_ops": ["sign"],
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
            "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
        }
    )
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # The recipient side:
    public_key = COSEKey.from_jwk(
        {
            "kid": "01",
            "kty": "OKP",
            "key_ops": ["verify"],
            "crv": "Ed25519",
            "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        }
    )
    decoded = cwt.decode(token, public_key)

Algorithms other than ``Ed25519`` are also supported. The following is an example of ``ES256``:

.. code-block:: console

    $ openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
    $ openssl ec -in private_key.pem -pubout -out public_key.pem

.. code-block:: python

    import cwt
    from cwt import COSEKey

    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="01")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="01")
    decoded = cwt.decode(token, public_key)

Other supported algorithms are listed in `Supported COSE Algorithms`_.

Encrypted CWT
-------------

Create an encrypted CWT with ``ChaCha20/Poly1305`` (ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag),
and decrypt it as follows:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
    )
    decoded = cwt.decode(token, enc_key)

Algorithms other than ``ChaCha20/Poly1305`` are also supported. The following is an example of
``AES-CCM-16-64-256``:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    enc_key = COSEKey.from_symmetric_key(alg="AES-CCM-16-64-256", kid="01")
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
    from cwt import COSEKey

    # A shared encryption key.
    enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="enc-01")

    # Creates a CWT with ES256 signing.
    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="sig-01")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
    )

    # Encrypts the signed CWT.
    nested = cwt.encode(token, enc_key)

    # Decrypts and verifies the nested CWT.
    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="sig-01")
    decoded = cwt.decode(nested, [enc_key, public_key])

CWT with User Settings
----------------------

The ``cwt`` in ``cwt.encode()`` and ``cwt.decode()`` above is a global ``CWT`` class instance created
with default settings in advance. The default settings are as follows:

* ``expires_in``: ``3600`` seconds. This is the default lifetime in seconds of CWTs.
* ``leeway``: ``60`` seconds. This is the default leeway in seconds for validating ``exp`` and ``nbf``.

If you want to change the settings, you can create your own ``CWT`` class instance as follows:

.. code-block:: python

    from cwt import COSEKey, CWT

    key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    mycwt = CWT.new(expires_in=3600 * 24, leeway=10)
    token = mycwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
    decoded = mycwt.decode(token, key)

CWT with User-Defined Claims
----------------------------

You can use your own claims as follows:

Note that such user-defined claim's key should be less than -65536.

.. code-block:: python

    import cwt
    from cwt import COSEKey

    # The sender side:
    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="01")
    token = cwt.encode(
        {
            1: "coaps://as.example",  # iss
            2: "dajiaji",  # sub
            7: b"123",  # cti
            -70001: "foo",
            -70002: ["bar"],
            -70003: {"baz": "qux"},
            -70004: 123,
        },
        private_key,
    )

    # The recipient side:
    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="01")
    raw = cwt.decode(token, public_key)
    assert raw[-70001] == "foo"
    assert raw[-70002][0] == "bar"
    assert raw[-70003]["baz"] == "qux"
    assert raw[-70004] == 123

    readable = Claims.new(raw)
    assert readable.get(-70001) == "foo"
    assert readable.get(-70002)[0] == "bar"
    assert readable.get(-70003)["baz"] == "qux"
    assert readable.get(-70004) == 123

User-defined claims can also be used with JSON-based claims as follows:

.. code-block:: python

    import cwt
    from cwt import Claims, COSEKey

    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="01")

    my_claim_names = {
        "ext_1": -70001,
        "ext_2": -70002,
        "ext_3": -70003,
        "ext_4": -70004,
    }

    cwt.set_private_claim_names(my_claim_names)
    token = cwt.encode(
        {
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": b"123",
            "ext_1": "foo",
            "ext_2": ["bar"],
            "ext_3": {"baz": "qux"},
            "ext_4": 123,
        },
        private_key,
    )
    claims.set_private_claim_names()

    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="01")

    raw = cwt.decode(token, public_key)
    readable = Claims.new(
        raw,
        private_claim_names=my_claim_names,
    )
    assert readable.get("ext_1") == "foo"
    assert readable.get("ext_2")[0] == "bar"
    assert readable.get("ext_3")["baz"] == "qux"
    assert readable.get("ext_4") == 123

CWT with PoP key
----------------

Create a CWT which has a PoP key as follows:

On the issuer side:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    # Prepares a signing key for CWT in advance.
    with open("./private_key_of_issuer.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

    # Sets the PoP key to a CWT for the presenter.
    token = cwt.encode(
        {
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": "123",
            "cnf": {
                "jwk": {  # Provided by the CWT presenter.
                    "kid": "presenter-01",
                    "kty": "OKP",
                    "use": "sig",
                    "crv": "Ed25519",
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
    from cwt import COSEKey

    # Prepares a private PoP key in advance.
    with open("./private_pop_key.pem") as key_file:
        pop_key_private = COSEKey.from_pem(key_file.read(), kid="presenter-01")

    # Receives a message (e.g., nonce)  from the recipient.
    msg = b"could-you-sign-this-message?"  # Provided by recipient.

    # Signs the message with the private PoP key.
    sig = pop_key_private.sign(msg)

    # Sends the msg and the sig with the CWT to the recipient.

On the CWT recipient side:

.. code-block:: python

    import cwt
    from cwt import Claims, COSEKey

    # Prepares the public key of the issuer in advance.
    with open("./public_key_of_issuer.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

    # Verifies and decodes the CWT received from the presenter.
    raw = cwt.decode(token, public_key)
    decoded = Claims.new(raw)

    # Extracts the PoP key from the CWT.
    extracted_pop_key = COSEKey.new(decoded.cnf)  #  = raw[8][1]

    # Then, verifies the message sent by the presenter
    # with the signature which is also sent by the presenter as follows:
    extracted_pop_key.verify(msg, sig)

In case of another PoP confirmation method ``Encrypted_COSE_Key``:

.. code-block:: python

    import cwt
    from cwt import Claims, COSEKey, EncryptedCOSEKey

    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

    enc_key = COSEKey.from_symmetric_key(
        "a-client-secret-of-cwt-recipient",  # Just 32 bytes!
        alg="ChaCha20/Poly1305",
        kid="recipient-01",
    )
    pop_key = COSEKey.from_symmetric_key(
        "a-client-secret-of-cwt-presenter",
        alg="HMAC 256/256",
        kid="presenter-01",
    )

    token = cwt.encode(
        {
            "iss": "coaps://as.example",
            "sub": "dajiaji",
            "cti": "123",
            "cnf": {
                # 'eck'(Encrypted Cose Key) is a keyword defined by this library.
                "eck": EncryptedCOSEKey.from_cose_key(pop_key, enc_key),
            },
        },
        private_key,
    )

    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
    raw = cwt.decode(token, public_key)
    decoded = Claims.new(raw)
    extracted_pop_key = EncryptedCOSEKey.to_cose_key(decoded.cnf, enc_key)
    # extracted_pop_key.verify(message, signature)

In case of another PoP confirmation method ``kid``:

.. code-block:: python

    import cwt
    from cwt import Claims, COSEKey

    with open("./private_key.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

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

    with open("./public_key.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")
    raw = cwt.decode(token, public_key)
    decoded = Claims.new(raw)
    # decoded.cnf(=raw[8][3]) is kid.

CWT for EUDCC (EU Digital COVID Certificate)
--------------------------------------------

Python CWT supports `Electronic Health Certificate Specification`_
and `EUDCC (EU Digital COVID Certificate)`_ compliant with `Technical Specifications for Digital Green Certificates Volume 1`_.

A following example shows how to verify an EUDCC:

.. code-block:: python

    import cwt
    from cwt import Claims, load_pem_hcert_dsc

    # A DSC(Document Signing Certificate) issued by a CSCA
    # (Certificate Signing Certificate Authority) quoted from:
    # https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/AT/2DCode/raw/1.json
    dsc = "-----BEGIN CERTIFICATE-----\nMIIBvTCCAWOgAwIBAgIKAXk8i88OleLsuTAKBggqhkjOPQQDAjA2MRYwFAYDVQQDDA1BVCBER0MgQ1NDQSAxMQswCQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMB4XDTIxMDUwNTEyNDEwNloXDTIzMDUwNTEyNDEwNlowPTERMA8GA1UEAwwIQVQgRFNDIDExCzAJBgNVBAYTAkFUMQ8wDQYDVQQKDAZCTVNHUEsxCjAIBgNVBAUTATEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASt1Vz1rRuW1HqObUE9MDe7RzIk1gq4XW5GTyHuHTj5cFEn2Rge37+hINfCZZcozpwQKdyaporPUP1TE7UWl0F3o1IwUDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFO49y1ISb6cvXshLcp8UUp9VoGLQMB8GA1UdIwQYMBaAFP7JKEOflGEvef2iMdtopsetwGGeMAoGCCqGSM49BAMCA0gAMEUCIQDG2opotWG8tJXN84ZZqT6wUBz9KF8D+z9NukYvnUEQ3QIgdBLFSTSiDt0UJaDF6St2bkUQuVHW6fQbONd731/M4nc=\n-----END CERTIFICATE-----"

    # An EUDCC (EU Digital COVID Certificate) quoted from:
    # https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/AT/2DCode/raw/1.json
    eudcc = bytes.fromhex(
        "d2844da20448d919375fc1e7b6b20126a0590133a4041a61817ca0061a60942ea001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d323658405812fce67cb84c3911d78e3f61f890d0c80eb9675806aebed66aa2d0d0c91d1fc98d7bcb80bf00e181806a9502e11b071325901bd0d2c1b6438747b8cc50f521"
    )

    public_key = load_pem_hcert_dsc(dsc)
    decoded = cwt.decode(eudcc, keys=[public_key])
    claims = Claims.new(decoded)
    # claims.hcert[1] ==
    # {
    #     'v': [
    #         {
    #             'dn': 1,
    #             'ma': 'ORG-100030215',
    #             'vp': '1119349007',
    #             'dt': '2021-02-18',
    #             'co': 'AT',
    #             'ci': 'URN:UVCI:01:AT:10807843F94AEE0EE5093FBC254BD813#B',
    #             'mp': 'EU/1/20/1528',
    #             'is': 'Ministry of Health, Austria',
    #             'sd': 2,
    #             'tg': '840539006',
    #         }
    #     ],
    #     'nam': {
    #         'fnt': 'MUSTERFRAU<GOESSINGER',
    #         'fn': 'Musterfrau-Gößinger',
    #         'gnt': 'GABRIELE',
    #         'gn': 'Gabriele',
    #     },
    #     'ver': '1.0.0',
    #     'dob': '1998-02-26',
    # }

.. _`Supported COSE Algorithms`: ./algorithms.html
.. _`Electronic Health Certificate Specification`: https://github.com/ehn-dcc-development/hcert-spec/blob/main/hcert_spec.md
.. _`EUDCC (EU Digital COVID Certificate)`: https://ec.europa.eu/info/live-work-travel-eu/coronavirus-response/safe-covid-19-vaccines-europeans/eu-digital-covid-certificate_en
.. _`Technical Specifications for Digital Green Certificates Volume 1`: https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf
