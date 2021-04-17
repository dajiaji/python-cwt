# Python CWT

A Python (>= 3.6) implementation of CBOR Web Token (CWT) and CBOR Object Signing and Encryption (COSE) compliant with:
- [RFC8392: CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
- [RFC8152: CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)

## Installing

Install with pip after cloning this repository.

```
pip install .
```

## Usase

Python CWT is easy to use.
If you already know about [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519),
little knowledge of [CBOR](https://tools.ietf.org/html/rfc7049), [COSE](https://tools.ietf.org/html/rfc8152)
and [CWT](https://tools.ietf.org/html/rfc8392) is required to use this library.

Followings are basic examples which create CWT, verify and decode it:

- [MACed CWT](#maced-cwt)
- [Signed CWT](#signed-cwt)
- [Encrypted CWT](#encrypted-cwt)
- [Nested CWT](#nested-cwt)

### MACed CWT

Create a MACed CWT, verify and decode it as follows:

```py
import cwt
from cwt import cose_key, claims

key = cose_key.from_symmetric_key("mysecretpassword")  # "HMAC256/256" is the default algorithm.
encoded = cwt.encode_and_mac(claims.from_json({"iss":"https://as.example", "sub":"dajiaji", "cti":"123"}), key)
decoded = cwt.decode(encoded, key)
```

CBOR-like structure (Dict[int, Any]) can be used as follows:

```py
import cwt

key = cwt.cose_key.from_symmetric_key("mysecretpassword")
encoded = cwt.encode_and_mac({1:"https://as.example", 2:"dajiaji", 7:b"123"}, key)
decoded = cwt.decode(encoded, key)
```

### Signed CWT

Create an ECDSA (with SHA-256) key pair:

```sh
$ openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
$ openssl ec -in private_key.pem -pubout -out public_key.pem
```

Create a Signed CWT, verify and decode it with the key pair  as follows:

```py
import cwt
from cwt import cose_key, claims

# Load PEM-formatted keys as COSE keys.
with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read())
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read())

# Encode with ES256 signing.
encoded = cwt.encode_and_sign(
    claims.from_json({"iss":"https://as.example", "sub":"dajiaji", "cti":"123"}), private_key)

# Verify and decode.
decoded = cwt.decode(encoded, public_key)
```

### Encrypted CWT

Create an Ed25519 key pair:

```sh
$ openssl genpkey -algorithm ed25519 -out private_key.pem
$ openssl pkey -in private_key.pem -pubout -out public_key.pem
```

Create an Encrypted CWT, verify and decode it with the key pair  as follows:

```py
import cwt
from cwt import cose_key, claims

# Load PEM-formatted keys as COSE keys.
with open("./private_key.pem") as key_file:
    private_key = cose_key.from_pem(key_file.read())
with open("./public_key.pem") as key_file:
    public_key = cose_key.from_pem(key_file.read())

# Encode with ES256 encryption.
encoded = cwt.encode_and_encrypt(
    claims.from_json({"iss":"https://as.example", "sub":"dajiaji", "cti":"123"}), private_key)

# Verify and decode.
decoded = cwt.decode(encoded, public_key)
```

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
