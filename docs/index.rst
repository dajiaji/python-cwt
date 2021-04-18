.. Python CWT documentation master file, created by
   sphinx-quickstart on Sun Apr 18 02:36:11 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Python CWT
=====================

Python CWT is a CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE)
implementation compliant with:

- `RFC8392: CBOR Web Token (CWT)`_
- `RFC8152: CBOR Object Signing and Encryption (COSE)`_

It is designed to make users who already know about `JSON Web Token (JWT)`_
be able to use it in ease. Little knowledge of `CBOR`_, `COSE`_, and `CWT`_
is required to use it.

You can install Python CWT with pip:

.. code-block:: console

    $ pip install cwt


And then, you can use it as follows:

.. code-block:: python

   import cwt
   from cwt import cose_key, claims

   key = cose_key.from_symmetric_key("mysecret")
   encoded = cwt.encode_and_mac(
       claims.from_json({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}),
       key,
   )
   decoded = cwt.decode(encoded, key)

Index
-----

.. toctree::
   :maxdepth: 2

   installation
   usage
   api
   algorithms
   changes

.. _`RFC8392: CBOR Web Token (CWT)`: https://tools.ietf.org/html/rfc8392
.. _`RFC8152: CBOR Object Signing and Encryption (COSE)`: https://tools.ietf.org/html/rfc8152
.. _`CBOR`: https://tools.ietf.org/html/rfc7049
.. _`COSE`: https://tools.ietf.org/html/rfc8152
.. _`CWT`: https://tools.ietf.org/html/rfc8392
.. _`JSON Web Token (JWT)`: https://tools.ietf.org/html/rfc7519
