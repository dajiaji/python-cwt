# Registered CWT Claims
CWT_CLAIM_NAMES = {
    "hcert": -260,  # map
    "EUPHNonce": -259,  # bstr
    "EATMAROEPrefix": -258,  # bstr
    "EAT-FDO": -257,  # array
    "iss": 1,  # text string
    "sub": 2,  # text string
    "aud": 3,  # text string
    "exp": 4,  # integer or floating-point number
    "nbf": 5,  # integer or floating-point number
    "iat": 6,  # integer or floating-point number
    "cti": 7,  # byte string
    "cnf": 8,  # map
    "nonce": 10,  # bstr or list[bstr]
    "ueid": 11,  # bstr
    "oemid": 13,  # bstr
    "seclevel": 14,  # integer(1, 2, 3, 4)
    "secboot": 15,  # bool
    "dbgstat": 16,  # integer(0, 1, 2, 3, 4)
    "location": 17,  # map
    "eat_profile": 18,  # uri / oid
    "submods": 20,  # map
    # "origination": 30,  # tstr(string-or-uri)
    # "uptime": 31,  # uint
    # "chip-version": 32,
    # "board-version": 33,
    # "device-version": 34,
    # "chip-version-scheme": 35,
    # "board-version-scheme": 36,
    # "device-version-scheme": 37,
    # "ean-chip-version": 38,
    # "ean-board-version": 39,
    # "ean-device-version": 40,
    # "intuse": 41,  # integer(1, 2, 3, 4, 5)
}

# COSE Header Parameters
COSE_HEADER_PARAMETERS = {
    "alg": 1,
    "crit": 2,
    "cty": 3,
    "content type": 3,
    "kid": 4,
    "iv": 5,
    "IV": 5,
    "Partial IV": 6,
    "counter signature": 7,
    "CounterSignature0": 9,
    "kid context": 10,
    "x5bag": 32,
    "x5c": 33,
    "x5chain": 33,
    "x5t": 34,
    "x5u": 35,
    "CUPHNonce": 256,
    "CUPHOwnerPubKey": 257,
}

# COSE key types
COSE_KEY_TYPES = {
    "OKP": 1,  # OCtet Key Pair
    "EC2": 2,  # Elliptic Curve Keys w/ x- and y-coordinate pair
    "EC": 2,  # Elliptic Curve Keys w/ x- and y-coordinate pair (JWK)
    "RSA": 3,  # RSA Key
    "Symmetric": 4,  # Symmetric Keys
    "oct": 4,  # Symmetric Keys (JWK)
    "HSS-LMS": 5,  # Public key for HSS/LMS hash-based digital signature
    "WalnutDSA": 6,  # WalnutDSA public key
}

# JWK Parameters
JWK_PARAMS_COMMON = {
    "kty": 1,
    "kid": 2,
    "alg": 3,
    # "use": *,
    "key_ops": 4,
}

JWK_PARAMS_OKP = {
    # "crv": -1,
    "x": -2,
    "d": -4,
}

JWK_PARAMS_EC = {
    # "crv": -1,
    "x": -2,
    "y": -3,
    "d": -4,
}

JWK_PARAMS_RSA = {
    "n": -1,
    "e": -2,
    "d": -3,
    "p": -4,
    "q": -5,
    "dp": -6,
    "dq": -7,
    "qi": -8,
    "oth": -9,
}

COSE_KEY_PARAMS_SYMMETRIC = {
    "k": -1,
}

# COSE key operation values.
COSE_KEY_OPERATION_VALUES = {
    "sign": 1,
    "verify": 2,
    "encrypt": 3,
    "decrypt": 4,
    "wrap key": 5,
    "unwrap key": 6,
    "derive key": 7,
    "derive bits": 8,
    "MAC create": 9,
    "MAC verify": 10,
    "wrapKey": 5,  # JWK
    "unwrapKey": 6,  # JWK
    "deriveKey": 7,  # JWK
    "deriveBits": 8,  # JWK
    "createMAC": 9,  # JWK-like lowerCamelCase
    "verifyMAC": 10,  # JWK-like lowerCamelCase
}

# COSE Algorithms for Content Encryption Key (CEK).
COSE_ALGORITHMS_CEK = {
    "A128GCM": 1,  # AES-GCM mode w/ 128-bit key, 128-bit tag
    "A192GCM": 2,  # AES-GCM mode w/ 192-bit key, 128-bit tag
    "A256GCM": 3,  # AES-GCM mode w/ 256-bit key, 128-bit tag
    "AES-CCM-16-64-128": 10,  # AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
    "AES-CCM-16-64-256": 11,  # AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
    "AES-CCM-64-64-128": 12,  # AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    "AES-CCM-64-64-256": 13,  # AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
    "ChaCha20/Poly1305": 24,  # ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
    "AES-CCM-16-128-128": 30,  # AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
    "AES-CCM-16-128-256": 31,  # AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
    "AES-CCM-64-128-128": 32,  # AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
    "AES-CCM-64-128-256": 33,  # AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
    # etc.
}

COSE_KEY_LEN = {
    -5: 256,  # AES Key Wrap w/ 256-bit key
    -4: 192,  # AES Key Wrap w/ 192-bit key
    -3: 128,  # AES Key Wrap w/ 128-bit key
    1: 128,  # AES-GCM mode w/ 128-bit key, 128-bit tag
    2: 192,  # AES-GCM mode w/ 192-bit key, 128-bit tag
    3: 256,  # AES-GCM mode w/ 256-bit key, 128-bit tag
    10: 128,  # AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
    11: 256,  # AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
    12: 128,  # AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    13: 256,  # AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
    24: 256,  # ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
    30: 128,  # AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
    31: 256,  # AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
    32: 128,  # AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
    33: 256,  # AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
}

COSE_ALGORITHMS_CKDM = {
    "direct+HKDF-SHA-512": -11,  # Shared secret w/ HKDF and SHA-512
    "direct+HKDF-SHA-256": -10,  # Shared secret w/ HKDF and SHA-256
    "direct": -6,  # direct
    # etc.
}

COSE_ALGORITHMS_KEY_WRAP = {
    "A256KW": -5,  # AES Key Wrap w/ 256-bit key
    "A192KW": -4,  # AES Key Wrap w/ 192-bit key
    "A128KW": -3,  # AES Key Wrap w/ 128-bit key
    # etc.
}

# COSE Algorithms for MAC.
COSE_ALGORITHMS_MAC = {
    "HMAC 256/64": 4,  # HMAC w/ SHA-256 truncated to 64 bits
    "HS256": 5,  # HMAC w/ SHA-256 (JWK)
    "HS384": 6,  # HMAC w/ SHA-384 (JWK)
    "HS512": 7,  # HMAC w/ SHA-512 (JWK)
    "HMAC 256/256": 5,  # HMAC w/ SHA-256
    "HMAC 384/384": 6,  # HMAC w/ SHA-384
    "HMAC 512/512": 7,  # HMAC w/ SHA-512
    "AES-MAC128/64": 14,  # AES-MAC 128-bit key, 64-bit tag
    "AES-MAC256/64": 15,  # AES-MAC 256-bit key, 64-bit tag
    "AES-MAC128/128": 25,  # AES-MAC 128-bit key, 128-bit tag
    "AES-MAC256/128": 26,  # AES-MAC 256-bit key, 128-bit tag
    # etc.
}

# COSE Algorithms for Signature with RSA.
COSE_ALGORITHMS_SIG_RSA = {
    "R1": -65535,  # RSASSA-PKCS1-v1_5 using SHA-1 (No plan to support)
    "RS512": -259,  # RSASSA-PKCS1-v1_5 using SHA-512
    "RS384": -258,  # RSASSA-PKCS1-v1_5 using SHA-384
    "RS256": -257,  # RSASSA-PKCS1-v1_5 using SHA-256
    "PS512": -39,  # RSASSA-PSS w/ SHA-512
    "PS384": -38,  # RSASSA-PSS w/ SHA-384
    "PS256": -37,  # RSASSA-PSS w/ SHA-256
    # etc.
}

# JOSE Algorithms supported.
JOSE_ALGORITHMS_SUPPORTED = {
    "RS512": -259,
    "RS384": -258,
    "RS256": -257,
    "ES256K": -47,
    "PS512": -39,
    "PS384": -38,
    "PS256": -37,
    "ES512": -36,
    "ES384": -35,
    "EdDSA": -8,
    "ES256": -7,
    "dir": -6,
    "A128GCM": 1,
    "A192GCM": 2,
    "A256GCM": 3,
    "HS256": 5,
    "HS384": 6,
    "HS512": 7,
}

JWK_TYPES = {
    "OKP": 1,
    "EC": 2,  # EC2
    "RSA": 3,
    "oct": 4,  # Symmetric
}

JWK_OPERATIONS = {
    "sign": 1,
    "verify": 2,
    "encrypt": 3,
    "decrypt": 4,
    "wrapKey": 5,
    "unwrapKey": 6,
    "deriveKey": 7,
    "deriveBits": 8,
}

JWK_ELLIPTIC_CURVES = {
    "P-256": 1,
    "P-384": 2,
    "P-521": 3,
    "X25519": 4,
    "X448": 5,
    "Ed25519": 6,
    "Ed448": 7,
    "secp256k1": 8,
}

# COSE Algorithms for recipients.
COSE_ALGORITHMS_RECIPIENT = dict(COSE_ALGORITHMS_CKDM, **COSE_ALGORITHMS_KEY_WRAP)

# COSE Algorithms for Symmetric Keys.
COSE_ALGORITHMS_SYMMETRIC = dict(COSE_ALGORITHMS_MAC, **COSE_ALGORITHMS_CEK)

# COSE Algorithms for RSA Keys.
COSE_ALGORITHMS_RSA = dict(COSE_ALGORITHMS_SIG_RSA)

# All of Supported COSE Algorithms.
COSE_ALGORITHMS = dict(COSE_ALGORITHMS_RSA, **COSE_ALGORITHMS_SYMMETRIC)

# COSE Named Algorithms for converting from JWK-like key.
COSE_NAMED_ALGORITHMS_SUPPORTED = dict(JOSE_ALGORITHMS_SUPPORTED, **COSE_ALGORITHMS)
