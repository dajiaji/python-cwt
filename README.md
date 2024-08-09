# Python CWT - A Python implementation of CWT/COSE

[![PyPI version](https://badge.fury.io/py/cwt.svg)](https://badge.fury.io/py/cwt)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cwt)
[![Documentation Status](https://readthedocs.org/projects/python-cwt/badge/?version=latest)](https://python-cwt.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/python-cwt/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/python-cwt/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/python-cwt)


Python CWT is a CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE)
implementation compliant with:
- [RFC9052: CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC9338: CBOR Object Signing and Encryption (COSE): Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html) - experimental
- [RFC8392: CWT (CBOR Web Token)](https://tools.ietf.org/html/rfc8392)
- [draft-07: Use of HPKE with COSE](https://www.ietf.org/archive/id/draft-ietf-cose-hpke-07.html) - experimental
- [draft-06: CWT Claims in COSE Headers](https://www.ietf.org/archive/id/draft-ietf-cose-cwt-claims-in-headers-06.html) - experimental
- and related various specifications. See [Referenced Specifications](#referenced-specifications).

It is designed to make users who already know about [JWS](https://tools.ietf.org/html/rfc7515)/[JWE](https://tools.ietf.org/html/rfc7516)/[JWT](https://tools.ietf.org/html/rfc7519)
be able to use it in ease. Little knowledge of [CBOR](https://tools.ietf.org/html/rfc7049)/[COSE](https://tools.ietf.org/html/rfc8152)/[CWT](https://tools.ietf.org/html/rfc8392)
is required to use it.

You can install Python CWT with pip:


```sh
$ pip install cwt
```

And then, you can use it as follows:

**COSE API**

```py
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

## You can get decoded protected/unprotected headers with the payload as follows:
# protected, unprotected, payload = recipient.decode_with_headers(encoded, mac_key)
# assert b"Hello world!" == payload
```

**CWT API**

```py
import cwt
from cwt import COSEKey, CWTClaims

mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

# The sender side:
token = encode(
    {
        CWTClaims.ISS: "coaps://as.example",
        CWTClaims.SUB: "dajiaji",
        CWTClaims.CTI: b"123",
    },
    mac_key,
)

# The recipient side:
decoded = decode(token, mac_key)
# decoded == {
#     CWTClaims.ISS: 'coaps://as.example',
#     CWTClaims.SUB: 'dajiaji',
#     CWTClaims.CTI: b'123',
#     CWTClaims.EXP: 1620088759,
#     CWTClaims.NBF: 1620085159,
#     CWTClaims.IAT: 1620085159
# }
```

Various usage examples are shown in this README.

See [Documentation](https://python-cwt.readthedocs.io/en/stable/) for details of the APIs.

## Index

- [Installation](#installation)
- [COSE Usage Examples](#cose-usage-examples)
    - [COSE MAC0](#cose-mac0)
        - [MAC with HMAC with SHA256](#mac-with-hmac-with-sha256)
        - [Countersign (MAC0)](#countersign-mac0)
    - [COSE MAC](#cose-mac)
        - [Direct Key Distribution](#direct-key-distribution-for-mac)
        - [Direct Key with KDF](#direct-key-with-kdf-for-mac)
        - [AES Key Wrap](#aes-key-wrap-for-mac)
        - [Direct key Agreement](#direct-key-agreement-for-mac)
        - [Key Agreement with Key Wrap](#key-agreement-with-key-wrap-for-mac)
        - [Countersign (MAC)](#countersign-mac)
        - [COSE-HPKE (MAC)](#cose-hpke-mac)
    - [COSE Encrypt0](#cose-encrypt0)
        - [Encryption with ChaCha20/Poly1305](#encryption-with-chacha20-poly1305)
        - [Countersign (Encrypt0)](#countersign-encrypt0)
        - [COSE-HPKE (Encrypt0)](#cose-hpke-encrypt0)
    - [COSE Encrypt](#cose-encrypt)
        - [Direct Key Distribution](#direct-key-distribution-for-encryption)
        - [Direct Key with KDF](#direct-key-with-kdf-for-encryption)
        - [AES Key Wrap](#aes-key-wrap-for-encryption)
        - [Direct key Agreement](#direct-key-agreement-for-encryption)
        - [Key Agreement with Key Wrap](#key-agreement-with-key-wrap-for-encryption)
        - [Countersign (Encrypt)](#countersign-encrypt)
        - [COSE-HPKE (Encrypt)](#cose-hpke-encrypt)
    - [COSE Signature1](#cose-signature1)
        - [Sign1 with EC P-256](#sign1-with-ec-p-256)
        - [Countersign (Sign1)](#countersign-sign1)
    - [COSE Signature](#cose-signature)
        - [Sign with EC P-256](#sign-with-ec-p-256)
        - [Countersign (Sign)](#countersign-sign)
- [CWT Usage Examples](#cwt-usage-examples)
    - [MACed CWT](#maced-cwt)
    - [Signed CWT](#signed-cwt)
    - [Encrypted CWT](#encrypted-cwt)
    - [Nested CWT](#nested-cwt)
    - [CWT with User Settings (e.g., expires\_in)](#cwt-with-user-settings)
    - [CWT with User-Defined Claims](#cwt-with-user-defined-claims)
    - [CWT with CWT claims in COSE headers](#cwt-with-cwt-claims-in-cose-headers)
    - [CWT with PoP Key](#cwt-with-pop-key)
    - [CWT with Private CA](#cwt-with-private-ca)
    - [CWT for EUDCC (EU Digital COVID Certificate)](#cwt-for-eudcc-eu-digital-covid-certificate)
- [API Reference](#api-reference)
- [Supported CWT Claims](#supported-cwt-claims)
- [Supported COSE Algorithms](#supported-cose-algorithms)
- [Referenced Specifications](#referenced-specifications)
- [Tests](#tests)
- [Contributing](#contributing)

## Installation

Install with pip:

```
pip install cwt
```

## COSE Usage Examples

Followings are typical and basic examples which encode various types of COSE messages and decode them.

See [API Reference](https://python-cwt.readthedocs.io/en/stable/api.html#cwt.COSE).

### COSE MAC0

#### MAC with HMAC with SHA256

Create a COSE MAC0 message, verify and decode it as follows:

```py
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
```

Following two samples are other ways of writing the above example.

CBOR object can be used for `protected` and `unprotected` header parameters as follows:

```py
from cwt import COSE, COSEHeaders, COSEKey

mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

# The sender side:
sender = COSE.new()
encoded = sender.encode(
    b"Hello world!",
    mac_key,
    protected={COSEHeaders.ALG: 5},
    unprotected={COSEHeaders.KID: b"01"},
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, mac_key)
```

`alg_auto_inclusion` and `kid_auto_inclusion` can be used to omit to specify `alg` and `kid` header parameters respectively as follows:

```py
from cwt import COSE, COSEKey

mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

# The sender side:
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    mac_key,
    # protected={"alg": "HS256"},
    # unprotected={"kid": "01"},
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, mac_key)
```

#### Countersign (MAC0)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to a MACed COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.

```py
from cwt import COSE, COSEKey, COSEMessage

mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

# The sender side:
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", mac_key)

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(countersigned, mac_key)
try:
    sig = COSEMessage.loads(countersigned).counterverify(pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```

### COSE MAC

#### Direct Key Distribution for MAC

The direct key distribution shares a MAC key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE MAC message, verify and decode it with the direct
key distribution method.

```py
from cwt import COSE, COSEKey, Recipient

mac_key = COSEKey.generate_symmetric_key(alg="HS512", kid="01")

# The sender side:
r = Recipient.new(unprotected={"alg": "direct", "kid": mac_key.kid})

sender = COSE.new()
encoded = sender.encode(
    b"Hello world!", mac_key, protected={"alg": "HS512"}, recipients=[r]
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, mac_key)
```

#### Direct Key with KDF for MAC


```py
from secrets import token_bytes
from cwt import COSE, COSEKey, Recipient

shared_material = token_bytes(32)
shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

# The sender side:
r = Recipient.new(
    unprotected={
        "alg": "direct+HKDF-SHA-256",
        "salt": "aabbccddeeffgghh",
    },
    context={"alg": "HS256"},
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    shared_key,
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(
    encoded, shared_key, context={"alg": "HS256"}
)
```

#### AES Key Wrap for MAC

The AES key wrap algorithm can be used to wrap a MAC key as follows:

```py
from cwt import COSE, COSEKey, Recipient

enc_key = COSEKey.from_jwk(
    {
        "kty": "oct",
        "kid": "01",
        "alg": "A128KW",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
    }
)

# The sender side:
mac_key = COSEKey.generate_symmetric_key(alg="HS512")
r = Recipient.new(unprotected={"alg": "A128KW"}, sender_key=enc_key)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", mac_key, recipients=[r])

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, enc_key)
```

#### Direct Key Agreement for MAC

The direct key agreement methods can be used to create a shared secret. A KDF (Key Distribution Function) is then
applied to the shared secret to derive a key to be used to protect the data.
The follwing example shows a simple way to make a COSE Encrypt message, verify and decode it with the direct key
agreement methods.

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
# The following key is provided by the recipient in advance.
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
r = Recipient.new(
    unprotected={"alg": "ECDH-ES+HKDF-256"},
    recipient_key=pub_key,
    context={"alg": "HS256"},
)
sender = COSE.new()
encoded = sender.encode(
    b"Hello world!",
    protected={"alg": "HS256"},
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
recipient = COSE.new()
# The enc_key will be derived in decode() with priv_key and
# the sender's public key which is conveyed as the recipient
# information structure in the COSE Encrypt message (encoded).
assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})
```

#### Key Agreement with Key Wrap for MAC


```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
mac_key = COSEKey.generate_symmetric_key(alg="HS256")
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "alg": "ECDH-ES+A128KW",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
r = Recipient.new(
    unprotected={"alg": "ECDH-ES+A128KW"},
    recipient_key=pub_key,
    context={"alg": "HS256"},
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    mac_key,
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "alg": "ECDH-ES+A128KW",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    }
)
assert b"Hello world!" == recipient.decode(encoded, priv_key, context={"alg": "HS256"})
```

#### Countersign (MAC)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to a MACed COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.


```py
from cwt import COSE, COSEKey, COSEMessage, Recipient

mac_key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")

# The sender side:
r = Recipient.new(unprotected={"alg": "direct", "kid": mac_key.kid})
sender = COSE.new()
encoded = sender.encode(
    b"Hello world!", mac_key, protected={"alg": "HS256"}, recipients=[r]
)

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(countersigned, mac_key)
try:
    sig = COSEMessage.loads(countersigned).counterverify(pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```


#### COSE-HPKE (MAC)

**Experimental Implementation. DO NOT USE for production.**

Create a COSE-HPKE MAC message, verify and decode it as follows:

```py
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, Recipient

# The sender side:
mac_key = COSEKey.generate_symmetric_key(alg="HS256")
rpk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)
r = Recipient.new(
    protected={
        COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
    },
    unprotected={
        COSEHeaders.KID: b"01",  # kid: "01"
    },
    recipient_key=rpk,
)
sender = COSE.new()
encoded = sender.encode(
    b"This is the content.",
    mac_key,
    protected={COSEHeaders.ALG: COSEAlgs.HS256},
    recipients=[r],
)

# The recipient side:
rsk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    }
)
recipient = COSE.new()
assert b"This is the content." == recipient.decode(encoded, rsk)
```

### COSE Encrypt0

#### Encryption with ChaCha20/Poly1305

Create a COSE Encrypt0 message and decrypt it as follows:

```py
from cwt import COSE, COSEKey

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", enc_key, unprotected={COSEHeaders.IV: nonce})

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, enc_key)
```

The following sample is another way of writing the above:

```py
from cwt import COSE, COSEKey

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
sender = COSE.new()
encoded = sender.encode(
    b"Hello world!",
    enc_key,
    protected={"alg": "ChaCha20/Poly1305"},
    unprotected={"kid": "01", "iv": nonce},
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, enc_key)
```

#### Countersign (Encrypt0)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to an encrypted COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.

```py
from cwt import COSE, COSEKey, COSEMessage

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", enc_key, unprotected={COSEHeaders.IV: nonce})

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(countersigned, enc_key)
try:
    sig = COSEMessage.loads(countersigned).counterverify(pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```

#### COSE-HPKE (Encrypt0)

**Experimental Implementation. DO NOT USE for production.**

Create a COSE-HPKE Encrypt0 message and decrypt it as follows:

```py
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey

# The sender side:
rpk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)

sender = COSE.new()
encoded = sender.encode(
    b"This is the content.",
    rpk,
    protected={
        COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
    },
    unprotected={
        COSEHeaders.KID: b"01",  # kid: "01"
    },
)

# The recipient side:
rsk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    }
)
recipient = COSE.new()
assert b"This is the content." == recipient.decode(encoded, rsk)
```

### COSE Encrypt

#### Direct Key Distribution for encryption

The direct key distribution shares a MAC key between the sender and the recipient that is used directly.
The follwing example shows the simplest way to make a COSE MAC message, verify and decode it with the direct
key distribution method.

```py
from cwt import COSE, COSEHeaders, COSEKey, Recipient

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
r = Recipient.new(unprotected={"alg": "direct"})
# r = Recipient.new(unprotected={COSEHeaders.ALG: -6}) # is also acceptable.

sender = COSE.new()
encoded = sender.encode(
    b"Hello world!",
    enc_key,
    protected={"alg": "ChaCha20/Poly1305"},
    # protected={COSEHeaders.ALG: 24},  # is also acceptable.
    unprotected={"kid": enc_key.kid, "iv": nonce},
    # unprotected={COSEHeaders.KID: enc_key.kid, COSEHeaders.IV: nonce},  # is also acceptable.
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, enc_key)
```

#### Direct Key with KDF for encryption


```py
from cwt import COSE, COSEKey, Recipient

shared_material = token_bytes(32)
shared_key = COSEKey.from_symmetric_key(shared_material, kid="01")

# The sender side:
r = Recipient.new(
    unprotected={
        "alg": "direct+HKDF-SHA-256",
        "salt": "aabbccddeeffgghh",
    },
    context={"alg": "A256GCM"},
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    shared_key,
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(
    encoded, shared_key, context={"alg": "A256GCM"}
)
```

#### AES Key Wrap for encryption

The AES key wrap algorithm can be used to wrap a MAC key as follows:

```py
from cwt import COSE, COSEKey, Recipient

wrapping_key = COSEKey.from_jwk(
    {
        "kty": "oct",
        "alg": "A128KW",
        "kid": "01",
        "k": "hJtXIZ2uSN5kbQfbtTNWbg",  # A shared wrapping key
    }
)

# The sender side:
enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305")
r = Recipient.new(
    unprotected={"alg": "A128KW"},
    sender_key=wrapping_key,
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", key=enc_key, recipients=[r])

# The recipient side:
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, wrapping_key)
```

#### Direct Key Agreement for encryption

The direct key agreement methods can be used to create a shared secret. A KDF (Key Distribution Function) is then
applied to the shared secret to derive a key to be used to protect the data.
The follwing example shows a simple way to make a COSE Encrypt message, verify and decode it with the direct key
agreement methods.

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
r = Recipient.new(
    unprotected={"alg": "ECDH-ES+HKDF-256"},
    recipient_key=pub_key,
    context={"alg": "A128GCM"},
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
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
assert b"Hello world!" == recipient.decode(
    encoded, priv_key, context={"alg": "A128GCM"}
)
```

#### Key Agreement with Key Wrap for encryption

```py
from cwt import COSE, COSEKey, Recipient

# The sender side:
enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
nonce = enc_key.generate_nonce()
r_pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "kid": "meriadoc.brandybuck@buckland.example",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    }
)
s_priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-SS+A128KW",
        "x": "7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU",
        "y": "DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo",
        "d": "Uqr4fay_qYQykwcNCB2efj_NFaQRRQ-6fHZm763jt5w",
    }
)
r = Recipient.new(
    unprotected={"alg": "ECDH-SS+A128KW"},
    sender_key=s_priv_key,
    recipient_key=r_pub_key,
    context={"alg": "A128GCM"},
)
sender = COSE.new(alg_auto_inclusion=True)
encoded = sender.encode(
    b"Hello world!",
    key=enc_key,
    unprotected={COSEHeaders.IV: nonce},
    recipients=[r],
)

# The recipient side:
recipient = COSE.new()
r_priv_key = COSEKey.from_jwk(
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
assert b"Hello world!" == recipient.decode(
    encoded, r_priv_key, context={"alg": "A128GCM"}
)
```

#### Countersign (Encrypt)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to an encrypted COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.

```py
from cwt import COSE, COSEKey, COSEMessage, Recipient

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")

# The sender side:
nonce = enc_key.generate_nonce()
r = Recipient.new(unprotected={"alg": "direct"})

sender = COSE.new()
encoded = sender.encode(
    b"Hello world!",
    enc_key,
    protected={"alg": "ChaCha20/Poly1305"},
    unprotected={"kid": enc_key.kid, "iv": nonce},
    recipients=[r],
)

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

# The recipient side:
pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(countersigned, enc_key)

try:
    sig = COSEMessage.loads(countersigned).counterverify(pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```

#### COSE-HPKE (Encrypt)

**Experimental Implementation. DO NOT USE for production.**

Create a COSE-HPKE Encrypt message and decrypt it as follows:

```py
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, Recipient

# The sender side:
enc_key = COSEKey.generate_symmetric_key(alg="A128GCM")
rpk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)
r = Recipient.new(
    protected={
        COSEHeaders.ALG: COSEAlgs.HPKE_BASE_P256_SHA256_AES128GCM,
    },
    unprotected={
        COSEHeaders.KID: b"01",  # kid: "01"
    },
    recipient_key=rpk,
)
sender = COSE.new()
encoded = sender.encode(
    b"This is the content.",
    enc_key,
    protected={
        COSEHeaders.ALG: 1,  # alg: "A128GCM"
    },
    recipients=[r],
)

# The recipient side:
rsk = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    }
)
recipient = COSE.new()
assert b"This is the content." == recipient.decode(encoded, rsk)
```

### COSE Signature1

#### Sign1 with EC P-256

Create a COSE Signature1 message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey, Signer

# The sender side:
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    }
)
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", priv_key)

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
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, pub_key)
```

#### Countersign (Sign1)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to a signed COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.

```py
from cwt import COSE, COSEKey, COSEMessage

# The sender side:
priv_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    }
)
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
encoded = sender.encode(b"Hello world!", priv_key)

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

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
notary_pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(countersigned, pub_key)
try:
    sig = COSEMessage.loads(countersigned).counterverify(notary_pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```

### COSE Signature

#### Sign with EC P-256

Create a COSE Signature message, verify and decode it as follows:

```py
from cwt import COSE, COSEKey, Signer

# The sender side:
signer = Signer.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    },
)
sender = COSE.new()
encoded = sender.encode(b"Hello world!", signers=[signer])

# The recipient side:
recipient = COSE.new()
pub_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    }
)
assert b"Hello world!" == recipient.decode(encoded, pub_key)
```

#### Countersign (Sign)

`python-cwt` supports [RFC9338: COSE Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html).
The notary below adds a countersignature to a signed COSE message.
The recipinet has to call `counterverify` to verify the countersignature explicitly.

```py
from cwt import COSE, COSEKey, COSEMessage, Signer

# The sender side:
signer = Signer.from_jwk(
    {
        "kty": "EC",
        "kid": "01",
        "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    },
)
sender = COSE.new()
encoded = sender.encode(b"Hello world!", signers=[signer])

# The notary side:
notary = Signer.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
        "d": "L8JS08VsFZoZxGa9JvzYmCWOwg7zaKcei3KZmYsj7dc",
    },
)
countersigned = COSEMessage.loads(encoded).countersign(notary).dumps()

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
notary_pub_key = COSEKey.from_jwk(
    {
        "kid": "01",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "2E6dX83gqD_D0eAmqnaHe1TC1xuld6iAKXfw2OVATr0",
    },
)
recipient = COSE.new()
assert b"Hello world!" == recipient.decode(encoded, pub_key)

try:
    sig = COSEMessage.loads(countersigned).counterverify(notary_pub_key)
except Exception as err:
    pytest.fail(f"failed to verify: {err}")
countersignature = COSEMessage.from_cose_signature(sig)
assert countersignature.protected[1] == -8  # alg: "EdDSA"
assert countersignature.unprotected[4] == b"01"  # kid: b"01"
```

## CWT Usage Examples

Followings are typical and basic examples which encode various types of CWTs, verify and decode them.

[CWT API](https://python-cwt.readthedocs.io/en/stable/api.html) in the examples are built
on top of [COSE API](https://python-cwt.readthedocs.io/en/stable/api.html#cwt.COSE).

See [API Reference](https://python-cwt.readthedocs.io/en/stable/api.html).

### MACed CWT

Create a MACed CWT with `HS256`, verify and decode it as follows:

```py
import cwt
from cwt import Claims, COSEKey

try:
    key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
    token = cwt.encode(
        {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key
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
```

A raw CWT structure (Dict[int, Any]) can also be used as follows:

```py
import cwt
from cwt import COSEKey, CWTClaims

key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
token = cwt.encode(
    {
        CWTClaims.ISS: "coaps://as.example",
        CWTClaims.SUB: "dajiaji",
        CWTClaims.CTI: b"123",
    },
    key,
)
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
```

JWKs can also be used instead of the PEM-formatted keys as follows:

```py
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
```

Signing algorithms other than `Ed25519` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Encrypted CWT

Create an encrypted CWT with `ChaCha20/Poly1305` and decrypt it as follows:

```py
import cwt
from cwt import COSEKey

enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="01")
token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, enc_key
)
decoded = cwt.decode(token, enc_key)
```

Encryption algorithms other than `ChaCha20/Poly1305` are listed in
[Supported COSE Algorithms](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

### Nested CWT

Create a signed CWT and encrypt it, and then decrypt and verify the nested CWT as follows.

```py
import cwt
from cwt import COSEKey

# A shared encryption key.
enc_key = COSEKey.generate_symmetric_key(alg="ChaCha20/Poly1305", kid="enc-01")

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
```

### CWT with User Settings

The `cwt` in `cwt.encode()` and `cwt.decode()` above is a global `CWT` class instance created
with default settings in advance. The default settings are as follows:
- `expires_in`: `3600` seconds. This is the default lifetime in seconds of CWTs.
- `leeway`: `60` seconds. This is the default leeway in seconds for validating `exp` and `nbf`.

If you want to change the settings, you can create your own `CWT` class instance as follows:

```py
from cwt import COSEKey, CWT

key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
mycwt = CWT.new(expires_in=3600 * 24, leeway=10)
token = mycwt.encode({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, key)
decoded = mycwt.decode(token, key)
```

### CWT with User-Defined Claims

You can use your own claims as follows:

Note that such user-defined claim's key should be less than -65536.

```py
import cwt
from cwt import COSEKey, CWTClaims

# The sender side:
with open("./private_key.pem") as key_file:
    private_key = COSEKey.from_pem(key_file.read(), kid="01")
token = cwt.encode(
    {
        CWTClaims.ISS: "coaps://as.example",  # iss
        CWTClaims.SUB: "dajiaji",  # sub
        CWTClaims.CTI: b"123",  # cti
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
```

User-defined claims can also be used with JSON-based claims as follows:

```py
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

set_private_claim_names(my_claim_names)
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

with open("./public_key.pem") as key_file:
    public_key = COSEKey.from_pem(key_file.read(), kid="01")

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


### CWT with CWT claims in COSE headers

Python CWT supports [CWT Claims in COSE Headers](https://www.ietf.org/archive/id/draft-ietf-cose-cwt-claims-in-headers-06.html)  experimentally.

If a CWT message has a CWT Claims header parameter in its protected header, `cwt.decode()` checks whether the values of the claims included in that parameter match the values of the corresponding claims in the payload. If they do not match, `VerifyError` is raised.

```py
from cwt import COSE, COSEHeaders, COSEKey, CWT, CWTClaims

enc_key = COSEKey.from_symmetric_key(alg="A128GCM", kid="01")

# The sender side:
sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
payload = cbor2.dumps(
    {
        CWTClaims.ISS: "coap://as.example.com",
        CWTClaims.SUB: "erikw",
        CWTClaims.AUD: "coap://light.example.com",
        CWTClaims.EXP: now() + 3600,
        CWTClaims.NBF: now(),
        CWTClaims.IAT: now(),
        CWTClaims.CTI: bytes.fromhex("0b71"),
    },
)
protected = {
    COSEHeaders.CWT_CLAIMS: {  # 13
        CWTClaims.ISS: "coap://as.example.com",
    }
}
token = sender.encode(payload, enc_key, protected)

# The recipient side:
recipient = CWT.new()
# `decode()` checks the validity of the CWT claims header parameter.
decoded = recipient.decode(token, enc_key)
assert decoded[CWTClaims.ISS] == "coap://as.example.com"
assert decoded[CWTClaims.SUB] == "erikw"
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

### CWT with Private CA

Python CWT supports the case of using an arbitrary private CA as a root of trust.
In this case, a COSE message sender needs to specify the trust relationship chaining up to the root CA by using `x5chain` header parameter.
On the other hand, a COSE message receiver needs to specify trusted root CAs by using `ca_certs` parameter of CWT/COSE constructor (`CWT.new()` or `COSE.new()`).

```py
import cwt
from cwt import Claims, COSEKey

# The sernder side:
with open("./private_key_of_cert.pem") as f:
    private_key = COSEKey.from_pem(f.read(), kid="01")

token = cwt.encode(
    {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}, private_key
)

# The recipient side:
public_key = COSEKey.from_jwk(
    {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": "P-256-01",
        "x": "oONCv1QoiajIbcW21Dqy6EnGvBTuF26GU7dy6JzOfXk",
        "y": "sl6k77K0TS36FW-TyEGLHY14ovZfdZ9DZWsbA8BTHGc",
        "x5c": [
            # The DER formatted X509 certificate which pairs with the private_key_of_cert.pem above.
            "MIIClDCCAXygAwIBAgIBBDANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xEDAOBgNVBAoMB2RhamlhamkxEzARBgNVBAMMCnB5dGhvbi1jd3QxIDAeBgkqhkiG9w0BCQEWEWRhamlhamlAZ21haWwuY29tMB4XDTIxMTAwMzEzMDE1MFoXDTMxMTAwMTEzMDE1MFowZDELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMQ0wCwYDVQQKDAR0ZXN0MRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUxHzAdBgkqhkiG9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASg40K_VCiJqMhtxbbUOrLoSca8FO4XboZTt3LonM59ebJepO-ytE0t-hVvk8hBix2NeKL2X3WfQ2VrGwPAUxxnoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAZFfvFbaDk_DmG2cPGTwqwnFok1QnH2Tzkjk7p4vs1ycWzEDltkhyzcJxTSHoQGdykf7fG8NCrEqfi1G3hOyAtGxVIVcqsI-KIJCESp43zrNz5HsbwEY8l5rvcwohKGlE_idIFt5IuDTv7vsg_FaCIDeruw0NrXAACnLTwksawsxaCvtY12U0wsI2aC2Sb6V3HL-OLgcN6ZWzZ054L88JllckYnqJB8wCVBzzX2K2sZH3yeS39oRWZOVG6fwXsX4k0fHFx-Fn6KlrBU15pbjMLMn0ow0X3Y8e7FOgfkkph-N7e2SxceXNjrLiumOdclPm9yGSWoGsOJdId53dPvqAsQ",
            # The root certificate which is used for signing the above certificate (optional).
            "MIIDrzCCApegAwIBAgIUIK_CYzdq4BLLVXqSclNBgXy6mgswDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRAwDgYDVQQKDAdkYWppYWppMRMwEQYDVQQDDApweXRob24tY3d0MSAwHgYJKoZIhvcNAQkBFhFkYWppYWppQGdtYWlsLmNvbTAgFw0yMTEwMDIyMzU0NTZaGA8yMDcxMDkyMDIzNTQ1NlowZjELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRAwDgYDVQQKDAdkYWppYWppMRMwEQYDVQQDDApweXRob24tY3d0MSAwHgYJKoZIhvcNAQkBFhFkYWppYWppQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANFg4sw-uPWbPBbkJuohXc89O0gaqG1H2i1wzxxka32XNKIdwrxOJvsB2eALo3q7dTqLKCgzrjdd5N07gi0KzqjoIXIXqKpV5tm0fP5gCzEOWgxySCfBJOJyyvO6WvYXdvukEBnL-48D8RSjQH9fQEju5RG0taFZE-0nQ7n3P0J-Q-OfBUEoRiHvCd8oUx0s-fBpKdfhMAbD1sGAQ9CokUFeWc49em8inNqia5xljBtSYo6_2Zx9eb7B53wvBC0EmtS4SRyksR2emlr6GxMj_EZW7hcTfZCM4V2JYXliuAEdxA0sB7q-WqLg4OvltBQxCBgTTEXRCzxj3XXZy7QyUacCAwEAAaNTMFEwHQYDVR0OBBYEFA9id2cL_Chjv6liRN3HD849TARsMB8GA1UdIwQYMBaAFA9id2cL_Chjv6liRN3HD849TARsMA8GA1UdEwEB_wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAArIej5eJN1OmD3l3ef9QzosCxKThNwqNY55CoSSC3IRl-IAXy9Lvx7cgiliwBgCv99RbXZ1ZnptTHC_1kzMzPhPg9pGKDowFP-rywaB9-NTuHTWQ4hkKDsru5dpf75ILNI5PTUi1iiBM7TdgSerpEVroUWZiOpGAdlKkmE1h4gkR6eQY9Q0IvVXwagy_PPoQ1XO1i5Hyg3aXeDZBgkE7AuW9uxtYQHzg8JG2TNko_yp497yf_Ew4t6KzGDhSa8L1euMPtclALDWFhgl6WmYsHOqAOsyZOLwpsifWa533wI9mtTvLEg8TFKMOdU0sbAoQSbrrI9m4QS7mzDLchngj3E",
        ],
        "alg": "ES256",
    }
)

# The recipient can specify trusted CAs as follows:
decoder = CWT.new(ca_certs="/path/to/cacerts.pem")
decoded = decoder.decode(token, public_key)
assert 1 in decoded and decoded[1] == "coaps://as.example"
```

### CWT for EUDCC (EU Digital COVID Certificate)

Python CWT supports [Electronic Health Certificate Specification](https://github.com/ehn-dcc-development/hcert-spec/blob/main/hcert_spec.md)
and [EUDCC (EU Digital COVID Certificate)](https://ec.europa.eu/info/live-work-travel-eu/coronavirus-response/safe-covid-19-vaccines-europeans/eu-digital-covid-certificate_en) compliant with [Technical Specifications for Digital Green Certificates Volume 1](https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf)

A following example shows how to verify an EUDCC:

```py
import cwt
from cwt import load_pem_hcert_dsc

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
```

## API Reference

See [Documentation](https://python-cwt.readthedocs.io/en/stable/api.html).

## Supported CWT Claims

See [Documentation](https://python-cwt.readthedocs.io/en/stable/claims.html).

## Supported COSE Algorithms

See [Documentation](https://python-cwt.readthedocs.io/en/stable/algorithms.html).

## Referenced Specifications

Python CWT is (partially) compliant with following specifications:

- [RFC9052: CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC9338: CBOR Object Signing and Encryption (COSE): Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html) - experimental
- [RFC8812: COSE and JOSE Registrations for Web Authentication (WebAuthn) Algorithms](https://tools.ietf.org/html/rfc8812)
- [RFC8747: Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)](https://tools.ietf.org/html/rfc8747)
- [RFC8392: CWT (CBOR Web Token)](https://tools.ietf.org/html/rfc8392)
- [RFC8230: Using RSA Algorithms with COSE Messages](https://tools.ietf.org/html/rfc8230)
- [RFC9459: CBOR Object Signing and Encryption (COSE): AES-CTR and AES-CBC](https://www.rfc-editor.org/rfc/rfc9459.html) - experimental
- [RFC8152: CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [draft-07: Use of HPKE with COSE](https://www.ietf.org/archive/id/draft-ietf-cose-hpke-07.html) - experimental
- [draft-06: CWT Claims in COSE Headers](https://www.ietf.org/archive/id/draft-ietf-cose-cwt-claims-in-headers-06.html) - experimental
- [Electronic Health Certificate Specification](https://github.com/ehn-dcc-development/hcert-spec/blob/main/hcert_spec.md)
- [Technical Specifications for Digital Green Certificates Volume 1](https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf)

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.
