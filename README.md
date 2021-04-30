# Python CWT

[![PyPI version](https://badge.fury.io/py/cwt.svg)](https://badge.fury.io/py/cwt)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cwt)
[![Documentation Status](https://readthedocs.org/projects/python-cwt/badge/?version=latest)](https://python-cwt.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/python-cwt/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/python-cwt/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/python-cwt)


A Python implementation of CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE) compliant with:
- [RFC8392: CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
- [RFC8152: CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)

See [Document](https://python-cwt.readthedocs.io/en/stable/) for details.

## Installing

Install with pip:

```
pip install cwt
```

## Usase

Python CWT is an easy-to-use CWT/COSE library a little bit inspired by [PyJWT](https://github.com/jpadilla/pyjwt).
If you already know about [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519),
little knowledge of [CBOR](https://tools.ietf.org/html/rfc7049), [COSE](https://tools.ietf.org/html/rfc8152)
and [CWT](https://tools.ietf.org/html/rfc8392) is required to use this library.

Followings are typical and basic examples which encode CWT, verify and decode it:

- [MACed CWT](#maced-cwt)
- [Signed CWT](#signed-cwt)
- [Encrypted CWT](#encrypted-cwt)
- [Nested CWT](#nested-cwt)

See [Usage Examples](https://python-cwt.readthedocs.io/en/latest/usage.html) for details.

### MACed CWT

Encode a MACed CWT, verify and decode it as follows:

```py
import cwt
from cwt import cose_key

key = cose_key.from_symmetric_key(alg="HMAC 256/256")
token = cwt.encode({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, key)
decoded = cwt.decode(token, key)
```

CBOR-like structure (Dict[int, Any]) can also be used as follows:

```py
import cwt
from cwt import cose_key

key = cose_key.from_symmetric_key(alg="HMAC 256/256")
token = cwt.encode({1: "https://as.example", 2: "dajiaji", 7: b"123"}, key)
decoded = cwt.decode(token, key)
```

Algorithms other than `HMAC 256/256` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Signed CWT

Create an `Ed25519` (Ed25519 for use w/ EdDSA only) key pair:

```sh
$ openssl genpkey -algorithm ed25519 -out private_key.pem
$ openssl pkey -in private_key.pem -pubout -out public_key.pem
```

Encode a Signed CWT, verify and decode it with the key pair as follows:

```py
import cwt
from cwt import cose_key

# Load PEM-formatted keys as COSE keys.
with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read())
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read())


# Encode with Ed25519 signing.
token = cwt.encode({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, private_key)

# Verify and decode.
decoded = cwt.decode(token, public_key)
```

Algorithms other than `Ed25519` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Encrypted CWT

Encode an encrypted CWT with `ChaCha20/Poly1305` (ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag),
and decrypt it as follows:

```py
import cwt
from cwt import cose_key

enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
token = cwt.encode({"iss": "https://as.example", "sub": "dajiaji", "cti": "123"}, enc_key)
decoded = cwt.decode(token, enc_key)
```

Algorithms other than `ChaCha20/Poly1305` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Nested CWT

Encode a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

```py
import cwt
from cwt import cose_key

# Load PEM-formatted keys as COSE keys.
with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read())
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read())

# Encode with ES256 signing.
token = cwt.encode({"iss": "https://as.example", "sub": "dajiaji", "cti": "124"}, private_key)

# Encrypt the signed CWT.
enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
nested = cwt.encode(token, enc_key)

# Decrypt and verify the nested CWT.
decoded = cwt.decode(nested, [enc_key, public_key])
```

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
