# Python CWT

[![PyPI version](https://badge.fury.io/py/cwt.svg)](https://badge.fury.io/py/cwt)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cwt)
[![Documentation Status](https://readthedocs.org/projects/python-cwt/badge/?version=latest)](https://python-cwt.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/python-cwt/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/python-cwt/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/python-cwt)


Python CWT is a CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE)
implementation compliant with:
- [RFC8392: CWT (CBOR Web Token)](https://tools.ietf.org/html/rfc8392)
- [RFC8152: COSE (CBOR Object Signing and Encryption)](https://tools.ietf.org/html/rfc8152)
- and related various specifications. See [Referenced Specifications](#referenced-specifications).

It is designed to make users who already know about [JWS](https://tools.ietf.org/html/rfc7515)/[JWE](https://tools.ietf.org/html/rfc7516)/[JWT](https://tools.ietf.org/html/rfc7519)
be able to use it in ease. Little knowledge of [CBOR](https://tools.ietf.org/html/rfc7049)/[COSE](https://tools.ietf.org/html/rfc8152)/[CWT](https://tools.ietf.org/html/rfc8392)
is required to use it.

You can install Python CWT with pip:


```sh
$ pip install cwt
```

And then, you can use it as follows:

```py
>>> import cwt
>>> from cwt import COSEKey
>>> key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
>>> token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
>>> token.hex()
'd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a60c6a60b051a60c697fb061a60c697fb582019d4a89e141e3a8805ba1c90d81a8a2dd8261464dce379d8af8044d1cc062258'
>>> cwt.decode(token, key)
{1: 'coaps://as.example', 2: 'dajiaji', 7: b'123', 4: 1620088759, 5: 1620085159, 6: 1620085159}
```

See [Document](https://python-cwt.readthedocs.io/en/stable/) for details.

## Index

- [Installing](#installing)
- [CWT Usage Examples](#cwt-usage-examples)
    - [MACed CWT](#maced-cwt)
    - [Signed CWT](#signed-cwt)
    - [Encrypted CWT](#encrypted-cwt)
    - [Nested CWT](#nested-cwt)
    - [CWT with User Settings (e.g., expires\_in)](#cwt-with-user-settings)
    - [CWT with User-Defined Claims](#cwt-with-user-defined-claims)
    - [CWT with PoP Key](#cwt-with-pop-key)
- [COSE Usage Examples](#cose-usage-examples)
    - [COSE MAC0](#cose-mac0)
    - [COSE MAC](#cose-mac)
        - [Direct Key Distribution](#direct-key-distribution-for-mac)
        - [Direct Key with KDF](#direct-key-with-kdf-for-mac)
        - [AES Key Wrap](#aes-key-wrap-for-mac)
        - [Direct key Agreement](#direct-key-agreement-for-mac)
        - [Key Agreement with Key Wrap](#key-agreement-with-key-wrap-for-mac)
    - [COSE Encrypt0](#cose-encrypt0)
    - [COSE Encrypt](#cose-encrypt)
        - [Direct Key Distribution](#direct-key-distribution-for-encryption)
        - [Direct Key with KDF](#direct-key-with-kdf-for-encryption)
        - [AES Key Wrap](#aes-key-wrap-for-encryption)
        - [Direct key Agreement](#direct-key-agreement-for-encryption)
        - [Key Agreement with Key Wrap](#key-agreement-with-key-wrap-for-encryption)
    - [COSE Signature1](#cose-signature1)
    - [COSE Signature](#cose-signature)
- [API Reference](#api-reference)
- [Supported CWT Claims](#supported-cwt-claims)
- [Supported COSE Algorithms](#supported-cose-algorithms)
- [Referenced Specifications](#referenced-specifications)
- [Tests](#tests)

## Installing

Install with pip:

```
pip install cwt
```

## CWT Usage Examples

Followings are typical and basic examples which create various types of CWTs, verify and decode them.

[CWT API](https://python-cwt.readthedocs.io/en/stable/api.html) in the examples are built
on top of [COSE API](https://python-cwt.readthedocs.io/en/stable/api.html#cwt.COSE).

See [API Reference](https://python-cwt.readthedocs.io/en/stable/api.html) and
[CWT Usage Examples on document](https://python-cwt.readthedocs.io/en/stable/cwt_usage.html)
for more details.

### MACed CWT

Create a MACed CWT with `HS256`, verify and decode it as follows:

```py
import cwt
from cwt import Claims, COSEKey

try:
    key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
    token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
    decoded = cwt.decode(token, key)

    # If you want to treat the result like a JWT;
    readable = Claims.new(decoded)
    assert readable.iss == 'coaps://as.example'
    assert readable.sub == 'dajiaji'
    assert readable.cti == '123'
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
```

A raw CWT structure (Dict[int, Any]) can also be used as follows:

```py
import cwt
from cwt import COSEKey

key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
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
from cwt import COSEKey

with open("./private_key.pem") as key_file:
    private_key = COSEKey.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="01")


token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

decoded = cwt.decode(token, public_key)
```

JWKs can also be used instead of the PEM-formatted keys as follows:

```py
import cwt
from cwt import COSEKey

private_key = COSEKey.from_jwk({
    "kty": "OKP",
    "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    "use": "sig",
    "crv": "Ed25519",
    "kid": "01",
    "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    "alg": "EdDSA",
})
public_key = COSEKey.from_jwk({
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
from cwt import COSEKey

enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
token = cwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key)

decoded = cwt.decode(token, enc_key)
```

Encryption algorithms other than `ChaCha20/Poly1305` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Nested CWT

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

```py
import cwt
from cwt import COSEKey

with open("./private_key.pem") as key_file:
    private_key = COSEKey.from_pem(key_file.read(), kid="sig-01")
with open("./public_key.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="sig-01")

# Creates a CWT with ES256 signing.
token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

# Encrypts the signed CWT.
enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="enc-01")
nested = cwt.encode(token, enc_key)

# Decrypts and verifies the nested CWT.
decoded = cwt.decode(nested, [enc_key, public_key])
```

### CWT with User Settings

The `cwt` in `cwt.encode()` and `cwt.decode()` above is a global `CWT` class instance created
with default settings in advance. The default settings are as follows:
- `expires_in`: `3600` seconds. This is the default lifetime in seconds of CWTs.
- `leeway`: `60` seconds. This is the default leeway in seconds for validating `exp` and `nbf`.

If you want to change the settings, you can create your own `CWT` class instance as follows:

```py
from cwt import COSEKey, CWT

key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
mycwt = CWT.new(expires_in=3600*24, leeway=10)
token = mycwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
decoded = mycwt.decode(token, key)
```

### CWT with User-Defined Claims

You can use your own claims as follows:

Note that such user-defined claim's key should be less than -65536.

```py
import cwt
from cwt import COSEKey

with open("./private_key.pem") as key_file:
    private_key = COSEKey.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="01")
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
assert raw[-70001] == "foo"
assert raw[-70002][0] == "bar"
assert raw[-70003]["baz"] == "qux"
assert raw[-70004] == 123

readable = Claims.new(raw)
assert readable.get(-70001) == "foo"
assert readable.get(-70002)[0] == "bar"
assert readable.get(-70003)["baz"] == "qux"
assert readable.get(-70004) == 123
```

User-defined claims can also be used with JSON-based claims as follows:

```py
import cwt
from cwt import Claims, COSEKey

with open("./private_key.pem") as key_file:
    private_key = COSEKey.from_pem(key_file.read(), kid="01")
with open("./public_key.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="01")

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
raw = cwt.decode(token, public_key)
readable = Claims.new(
    raw,
    private_claims_names=my_claim_names,
)
assert readable.get("ext_1") == "foo"
assert readable.get("ext_2")[0] == "bar"
assert readable.get("ext_3")["baz"] == "qux"
assert readable.get("ext_4") == 123
```


### CWT with PoP Key

Python CWT supports [Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)](https://tools.ietf.org/html/rfc8747).
A CWT can include a PoP key as follows:

On the issuer side:

```py
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
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "kid": "presenter-01",
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
from cwt import COSEKey

# Prepares a private PoP key in advance.
with open("./private_pop_key.pem") as key_file:
    pop_key_private = COSEKey.from_pem(key_file.read(), kid="presenter-01")

# Receives a message (e.g., nonce)  from the recipient.
msg = b"could-you-sign-this-message?"  # Provided by recipient.

# Signs the message with the private PoP key.
sig = pop_key_private.sign(msg)

# Sends the msg and the sig with the CWT to the recipient.
```

On the CWT recipient side:

```py
import cwt
from cwt import Claims, COSEKey

# Prepares the public key of the issuer in advance.
with open("./public_key_of_issuer.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="issuer-01")

# Verifies and decodes the CWT received from the presenter.
raw = cwt.decode(token, public_key)
decoded = Claims.new(raw)

# Extracts the PoP key from the CWT.
extracted_pop_key = COSEKey.new(decoded.cnf)  # = raw[8][1]

# Then, verifies the message sent by the presenter
# with the signature which is also sent by the presenter as follows:
extracted_pop_key.verify(msg, sig)
```

[Usage Examples](https://python-cwt.readthedocs.io/en/stable/cwt_usage.html#cwt-with-pop-key)
shows other examples which use other confirmation methods for PoP keys.

## COSE Usage Examples

Followings are typical and basic examples which create various types of COSE messages, verify and decode them.

See [API Reference](https://python-cwt.readthedocs.io/en/stable/api.html#cwt.COSE) and
[COSE Usage Examples on document](https://python-cwt.readthedocs.io/en/stable/cose_usage.html) for more details.

### COSE MAC0

Create a COSE MAC0 message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey

mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = ctx.encode_and_mac(b"Hello world!", mac_key)
assert b"Hello world!" == ctx.decode(encoded, mac_key)
```

Following two samples are other ways of writing the above example:

```py
from cwt import COSE, COSEKey

mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
ctx = COSE.new()
encoded = ctx.encode_and_mac(
    b"Hello world!",
    mac_key,
    protected={"alg": "HS256"},
    unprotected={"kid": "01"},
)
assert b"Hello world!" == ctx.decode(encoded, mac_key)
```

```py
from cwt import COSE, COSEKey

mac_key = COSEKey.from_symmetric_key(alg="HS256", kid="01")
ctx = COSE.new()
encoded = ctx.encode_and_mac(
    b"Hello world!",
    mac_key,
    protected={1: 5},
    unprotected={4: b"01"},
)
assert b"Hello world!" == ctx.decode(encoded, mac_key)
```

### COSE MAC

#### Direct Key Distribution for MAC

The direct key distribution shares a MAC key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE MAC message, verify and decode it with the direct
key distribution method.

```py
from cwt import COSE, COSEKey, Recipient

# The sender makes a COSE MAC message as follows:
mac_key = COSEKey.from_symmetric_key(alg="HS512", kid="01")
r = Recipient.from_jwk({"alg": "direct"})
r.apply(mac_key)
ctx = COSE.new()
encoded = ctx.encode_and_mac(b"Hello world!", mac_key, recipients=[r])

# The recipient has the same MAC key and can verify and decode it:
assert b"Hello world!" == ctx.decode(encoded, mac_key)
```

#### Direct Key with KDF for MAC


```py
from secrets import token_bytes
from cwt import COSE, COSEKey, Recipient

shared_material = token_bytes(32)
shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

# The sender side:
r = Recipient.from_jwk(
    {
        "kty": "oct",
        "alg": "direct+HKDF-SHA-256",
        "salt": "aabbccddeeffgghh",
    },
)
mac_key = r.apply(shared_key, context={"alg": "HS256"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_mac(
    b"Hello world!",
    key=mac_key,
    recipients=[r],
)

# The recipient side:
assert b"Hello world!" == ctx.decode(encoded, shared_key, context={"alg": "HS256"})
```

#### AES Key Wrap for MAC

The AES key wrap algorithm can be used to wrap a MAC key as follows:

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
mac_key = COSEKey.from_symmetric_key(alg="HS512")
r = Recipient.from_jwk(
    {
        "alg": "A128KW",
        "kid": "01",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
    },
)
r.apply(mac_key)
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_mac(b"Hello world!", key=mac_key, recipients=[r])

# The recipient side:
shared_key = COSEKey.from_jwk(
    {
        "kty": "oct",
        "alg": "A128KW",
        "kid": "01",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",
    },
)
assert b"Hello world!" == ctx.decode(encoded, shared_key)
```

#### Direct Key Agreement for MAC

The direct key agreement methods can be used to create a shared secret. A KDF (Key Distribution Function) is then
applied to the shared secret to derive a key to be used to protect the data.
The follwing example shows a simple way to make a COSE Encrypt message, verify and decode it with the direct key
agreement methods (``ECDH-ES+HKDF-256`` with various curves).

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
r = Recipient.from_jwk(
    {
        "kty": "EC",
        "alg": "ECDH-ES+HKDF-256",
        "crv": "P-256",
    },
)
# The following key is provided by the recipient in advance.
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "alg": "ECDH-ES+HKDF-256",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
mac_key = r.apply(recipient_key=pub_key, context={"alg": "HS256"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_mac(
    b"Hello world!",
    key=mac_key,
    recipients=[r],
)

# The recipient side:
# The following key is the private key of the above pub_key.
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "alg": "ECDH-ES+HKDF-256",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
# The enc_key will be derived in decode() with priv_key and
# the sender's public key which is conveyed as the recipient
# information structure in the COSE Encrypt message (encoded).
assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "HS256"})
```

#### Key Agreement with Key Wrap for MAC


```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
mac_key = COSEKey.from_symmetric_key(alg="HS256")
r = Recipient.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-SS+A128KW",
        "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
        "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
        "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
    }
)
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "kid": "meriadoc.brandybuck@buckland.example",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
r.apply(mac_key, recipient_key=pub_key, context={"alg": "HS256"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_mac(
    b"Hello world!",
    key=mac_key,
    recipients=[r],
)

# The recipient side:
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-SS+A128KW",
        "kid": "meriadoc.brandybuck@buckland.example",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "HS256"})
```


### COSE Encrypt0

Create a COSE Encrypt0 message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey

enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
ctx = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = ctx.encode_and_encrypt(b"Hello world!", enc_key)
decoded = ctx.decode(encoded, enc_key)
```

### COSE Encrypt

#### Direct Key Distribution for encryption

The direct key distribution shares a MAC key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE MAC message, verify and decode it with the direct
key distribution method.

```py
from cwt import COSE, COSEKey, Recipient

enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
r = Recipient.from_jwk({"alg": "direct"})
r.apply(enc_key)
ctx = COSE.new()
encoded = ctx.encode_and_encrypt(
    b"Hello world!",
    enc_key,
    nonce=nonce,
    recipients=[r],
)

# The recipient side:
assert b"Hello world!" == ctx.decode(encoded, enc_key)
```

#### Direct Key with KDF for encryption


```py
from cwt import COSE, COSEKey, Recipient

shared_material = token_bytes(32)
shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

# The sender side:
r = Recipient.from_jwk(
    {
        "kty": "oct",
        "alg": "direct+HKDF-SHA-256",
        "salt": "aabbccddeeffgghh",
    },
)
enc_key = r.apply(shared_key, context={"alg": "A256GCM"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_encrypt(
    b"Hello world!",
    key=enc_key,
    recipients=[r],
)
# The recipient side:
assert b"Hello world!" == ctx.decode(encoded, shared_key, context={"alg": "A256GCM"})
```

#### AES Key Wrap for encryption

The AES key wrap algorithm can be used to wrap a MAC key as follows:

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
r = Recipient.from_jwk(
    {
        "kty": "oct",
        "alg": "A128KW",
        "kid": "01",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
    },
)
enc_key = COSEKey.from_symmetric_key(alg="ChaCha20/Poly1305")
r.apply(enc_key)
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_encrypt(b"Hello world!", key=enc_key, recipients=[r])

# The recipient side:
shared_key = COSEKey.from_jwk(
    {
        "kty": "oct",
        "alg": "A128KW",
        "kid": "01",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",
    },
)
assert b"Hello world!" == ctx.decode(encoded, shared_key)
```

#### Direct Key Agreement for encryption

The direct key agreement methods can be used to create a shared secret. A KDF (Key Distribution Function) is then
applied to the shared secret to derive a key to be used to protect the data.
The follwing example shows a simple way to make a COSE Encrypt message, verify and decode it with the direct key
agreement methods (``ECDH-ES+HKDF-256`` with various curves).

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
r = Recipient.from_jwk(
    {
        "kty": "OKP",
        "alg": "ECDH-ES+HKDF-256",
        "crv": "X25519",
    },
)
pub_key = COSEKey.from_jwk(
    {
        "kty": "OKP",
        "alg": "ECDH-ES+HKDF-256",
        "kid": "01",
        "crv": "X25519",
        "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
    }
)
enc_key = r.apply(recipient_key=pub_key, context={"alg": "A128GCM"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_encrypt(
    b"Hello world!",
    key=enc_key,
    recipients=[r],
)

# The recipient side:
priv_key = COSEKey.from_jwk(
    {
        "kty": "OKP",
        "alg": "ECDH-ES+HKDF-256",
        "kid": "01",
        "crv": "X25519",
        "x": "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
        "d": "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
    }
)
assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})
```

#### Key Agreement with Key Wrap for encryption

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
enc_key = COSEKey.from_symmetric_key(alg="A128GCM")
nonce = enc_key.generate_nonce()
r = Recipient.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-SS+A128KW",
        "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
        "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
        "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
    }
)
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "kid": "meriadoc.brandybuck@buckland.example",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
r.apply(enc_key, recipient_key=pub_key, context={"alg": "A128GCM"})
ctx = COSE.new(alg_auto_inclusion=True)
encoded = ctx.encode_and_encrypt(
    b"Hello world!",
    key=enc_key,
    nonce=nonce,
    recipients=[r],
)

# The recipient side:
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-SS+A128KW",
        "kid": "meriadoc.brandybuck@buckland.example",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
assert b"Hello world!" == ctx.decode(encoded, priv_key, context={"alg": "A128GCM"})
```

### COSE Signature1

Create a COSE Signature1 message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey, Signer

# The sender side:
signer = Signer.new(
    cose_key=COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "01",
            "crv": "P-256",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
        }
    ),
    protected={"alg": "ES256"},
    unprotected={"kid": "01"},
)
ctx = COSE.new()
encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)
assert b"Hello world!" == ctx.decode(encoded, pub_key)
```

### COSE Signature

Create a COSE Signature message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey, Signer

# The sender side:
signer = Signer.new(
    cose_key=COSEKey.from_jwk(
        {
            "kty": "EC",
            "kid": "01",
            "crv": "P-256",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
            "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
        }
    ),
    protected={1: -7},
    unprotected={4: b"01"},
)
ctx = COSE.new()
encoded = ctx.encode_and_sign(b"Hello world!", signers=[signer])

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)
assert b"Hello world!" == ctx.decode(encoded, pub_key)
```
## API Reference

See [Document](https://python-cwt.readthedocs.io/en/stable/api.html).

## Supported CWT Claims

See [Document](https://python-cwt.readthedocs.io/en/stable/claims.html).

## Supported COSE Algorithms

See [Document](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

## Referenced Specifications

Python CWT is (partially) compliant with following specifications:

- [RFC8152: CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [RFC8230: Using RSA Algorithms with COSE Messages](https://tools.ietf.org/html/rfc8230)
- [RFC8392: CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
- [RFC8747: Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)](https://tools.ietf.org/html/rfc8747)
- [RFC8812: COSE and JOSE Registrations for Web Authentication (WebAuthn) Algorithms](https://tools.ietf.org/html/rfc8812)

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
