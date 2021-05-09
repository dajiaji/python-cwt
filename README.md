# Python CWT

[![PyPI version](https://badge.fury.io/py/cwt.svg)](https://badge.fury.io/py/cwt)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cwt)
[![Documentation Status](https://readthedocs.org/projects/python-cwt/badge/?version=latest)](https://python-cwt.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/python-cwt/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/python-cwt/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/python-cwt)


A Python implementation of [CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
and [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152).

See [Document](https://python-cwt.readthedocs.io/en/stable/) for details:

- [Usage Examples](https://python-cwt.readthedocs.io/en/stable/usage.html)
- [API Reference](https://python-cwt.readthedocs.io/en/stable/api.html)
- [Supported CWT Claims](https://python-cwt.readthedocs.io/en/stable/claims.html)
- [Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html)
- [Referenced Specifications](https://python-cwt.readthedocs.io/en/stable/specs.html)

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

Followings are typical and basic examples which create CWT, verify and decode it:

- [MACed CWT](#maced-cwt)
- [Signed CWT](#signed-cwt)
- [Encrypted CWT](#encrypted-cwt)
- [Nested CWT](#nested-cwt)
- [CWT with User-Defined Claims](#cwt-with-user-defined-claims)
- [CWT with PoP Key](#cwt-with-pop-key)

See [Usage Examples](https://python-cwt.readthedocs.io/en/stable/usage.html) for details.

### MACed CWT

Create a MACed CWT with `HS256`, verify and decode it as follows:

```py
import cwt
from cwt import claims, cose_key

key = cose_key.from_symmetric_key(alg="HS256")  # == "HMAC 256/256"
token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)

decoded = cwt.decode(token, key)

# decoded == {
#     1: 'coaps://as.example',
#     2: 'dajiaji',
#     7: b'123',
#     4: 1620088759,
#     5: 1620085159,
#     6: 1620085159,
# }

# If you want to treat the result like a JWT;
readable = claims.from_dict(decoded)

# readable.iss == 'coaps://as.example'
# readable.sub == 'dajiaji'
# readable.cti == '123'
# readable.exp == 1620088759
# readable.nbf == 1620085159
# readable.iat == 1620085159
```

CBOR-like structure (Dict[int, Any]) can also be used as follows:

```py
import cwt
from cwt import cose_key

key = cose_key.from_symmetric_key(alg="HS256")
token = cwt.encode({1: "coaps://as.example", 2: "dajiaji", 7: b"123"}, key)

decoded = cwt.decode(token, key)
```

MAC algorithms other than `HS256` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Signed CWT

Create an `Ed25519` key pair:

```sh
$ openssl genpkey -algorithm ed25519 -out private_key.pem
$ openssl pkey -in private_key.pem -pubout -out public_key.pem
```

Create a Signed CWT with `Ed25519`, verify and decode it with the key pair as follows:

```py
import cwt
from cwt import cose_key

with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read(), kid="01")


token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

decoded = cwt.decode(token, public_key)
```

JWKs can also be used instead of the PEM-formatted keys as follows:

```py
import cwt
from cwt import cose_key

private_key = cose_key.from_jwk({
    "kty": "OKP",
    "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    "use": "sig",
    "crv": "Ed25519",
    "kid": "01",
    "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    "alg": "EdDSA",
})
public_key = cose_key.from_jwk({
    "kty": "OKP",
    "use": "sig",
    "crv": "Ed25519",
    "kid": "01",
    "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
})

token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

decoded = cwt.decode(token, public_key)
```

Signing algorithms other than `Ed25519` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Encrypted CWT

Create an encrypted CWT with `ChaCha20/Poly1305` and decrypt it as follows:

```py
import cwt
from cwt import cose_key

enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key)

decoded = cwt.decode(token, enc_key)
```

Encryption algorithms other than `ChaCha20/Poly1305` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Nested CWT

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

```py
import cwt
from cwt import cose_key

with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read(), kid="01")

# Creates a CWT with ES256 signing.
token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

# Encrypts the signed CWT.
enc_key = cose_key.from_symmetric_key(alg="ChaCha20/Poly1305")
nested = cwt.encode(token, enc_key)

# Decrypts and verifies the nested CWT.
decoded = cwt.decode(nested, [enc_key, public_key])
```

### CWT with User-Defined Claims

You can use your own claims as follows:

Note that such user-defined claim's key should be less than -65536.

```py
import cwt
from cwt import cose_key

with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read(), kid="01")
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
raw = cwt.decode(token, public_key)
# raw[-70001] == "foo"
# raw[-70002][0] == "bar"
# raw[-70003]["baz"] == "qux"
# raw[-70004] == 123
readable = claims.from_dict(raw)
# readable.get(-70001) == "foo"
# readable.get(-70002)[0] == "bar"
# readable.get(-70003)["baz"] == "qux"
# readable.get(-70004) == 123
```

User-defined claims can also be used with JSON-based claims as follows:

```py
import cwt
from cwt import claims, cose_key

with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read(), kid="01")

cwt.set_private_claim_names(
    {
        "ext_1": -70001,
        "ext_2": -70002,
        "ext_3": -70003,
        "ext_4": -70004,
    }
)
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
claims.set_private_claim_names(
    {
        "ext_1": -70001,
        "ext_2": -70002,
        "ext_3": -70003,
        "ext_4": -70004,
    }
)
raw = cwt.decode(token, public_key)
readable = claims.from_dict(raw)
# readable.get("ext_1") == "foo"
# readable.get("ext_2")[0] == "bar"
# readable.get("ext_3")["baz"] == "qux"
# readable.get("ext_4") == 123
```


### CWT with PoP Key

This library supports [Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)](https://tools.ietf.org/html/rfc8747).
A CWT can include a PoP key as follows:

On the issuer side:

```py
import cwt
from cwt import cose_key

# Prepares a signing key for CWT in advance.
with open("./private_key_of_issuer.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read(), kid="issuer-01")

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
```

On the CWT presenter side:

```py
import cwt
from cwt import cose_key

# Prepares a private PoP key in advance.
with open("./private_pop_key.pem") as key_file:
    pop_key_private = cose_key.from_pem(key_file.read(), kid="01")

# Receives a message (e.g., nonce)  from the recipient.
msg = b"could-you-sign-this-message?"  # Provided by recipient.

# Signs the message with the private PoP key.
sig = pop_key_private.sign(msg)

# Sends the msg and the sig with the CWT to the recipient.
```

On the CWT recipient side:

```py
import cwt
from cwt import claims, cose_key

# Prepares the public key of the issuer in advance.
with open("./public_key_of_issuer.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read(), kid="issuer-01")

# Verifies and decodes the CWT received from the presenter.
raw = cwt.decode(token, public_key)
decoded = claims.from_dict(raw)

# Extracts the PoP key from the CWT.
extracted_pop_key = cose_key.from_dict(decoded.cnf)  # = raw[8][1]

# Then, verifies the message sent by the presenter
# with the signature which is also sent by the presenter as follows:
extracted_pop_key.verify(msg, sig)
```

[Usage Examples](https://python-cwt.readthedocs.io/en/stable/usage.html#cwt-with-pop-key) shows other examples which
use other confirmation methods for PoP keys.

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
