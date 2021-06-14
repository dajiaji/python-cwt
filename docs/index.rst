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
- and related various specifications. See `Referenced Specifications`_.

It is designed to make users who already know about `JWS`_/`JWE`_/`JWT`_
be able to use it in ease. Little knowledge of `CBOR`_/`COSE`_/`CWT`_
is required to use it.

You can install Python CWT with pip:

.. code-block:: console

    $ pip install cwt


And then, you can use it as follows:

.. code-block:: pycon

    >>> import cwt
    >>> from cwt import COSEKey
    >>> key = COSEKey.from_symmetric_key(alg="HS256")
    >>> token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
    >>> token.hex()
    'd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a60c6a60b051a60c697fb061a60c697fb582019d4a89e141e3a8805ba1c90d81a8a2dd8261464dce379d8af8044d1cc062258'
    >>> cwt.decode(token, key)
    {1: 'coaps://as.example', 2: 'dajiaji', 7: b'123', 4: 1620088759, 5: 1620085159, 6: 1620085159}

Index
-----

.. toctree::
   :maxdepth: 2

   installation
   cwt_usage
   cose_usage
   api
   claims
   algorithms
   specs
   changes

.. _`RFC8392: CBOR Web Token (CWT)`: https://tools.ietf.org/html/rfc8392
.. _`RFC8152: CBOR Object Signing and Encryption (COSE)`: https://tools.ietf.org/html/rfc8152
.. _`CBOR`: https://tools.ietf.org/html/rfc7049
.. _`COSE`: https://tools.ietf.org/html/rfc8152
.. _`CWT`: https://tools.ietf.org/html/rfc8392
.. _`JWS`: https://tools.ietf.org/html/rfc7515
.. _`JWE`: https://tools.ietf.org/html/rfc7516
.. _`JWT`: https://tools.ietf.org/html/rfc7519
.. _`Referenced Specifications`: ./specs.html
