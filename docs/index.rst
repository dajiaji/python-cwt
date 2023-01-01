.. Python CWT documentation master file, created by
   sphinx-quickstart on Sun Apr 18 02:36:11 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Python CWT
=====================

Python CWT is a CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE)
implementation compliant with `various COSE related specifications`_.

You can install Python CWT with pip:

.. code-block:: console

    $ pip install cwt


And then, you can use it as follows:

COSE API:

.. code-block:: python

    from cwt import COSE, COSEKey

    mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

    # The sender side:
    sender = COSE.new()
    encoded = sender.encode(
        b"Hello world!",
        mac_key,
        protected={"alg": "HS256"},
        unprotected={"kid": "01"},
    )

    # The recipient side:
    recipient = COSE.new()
    assert b"Hello world!" == recipient.decode(encoded, mac_key)

CWT API:

.. code-block:: python

    import cwt
    from cwt import COSEKey

    mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

    # The sender side:
    token = encode({1: "coaps://as.example", 2: "dajiaji", 7: b"123"}, mac_key)

    # The recipient side:
    decoded = decode(token, mac_key)
    # decoded == {1: 'coaps://as.example', 2: 'dajiaji', 7: b'123', 4: 1620088759, 5: 1620085159, 6: 1620085159}


Index
-----

.. toctree::
   :maxdepth: 2

   installation
   api
   claims
   algorithms
   changes

.. _`various COSE related specifications`: https://github.com/dajiaji/python-cwt#referenced-specifications
