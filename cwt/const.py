from .enums import COSETypes

COSE_TAG_TO_TYPE = {
    16: COSETypes.ENCRYPT0,
    96: COSETypes.ENCRYPT,
    17: COSETypes.MAC0,
    97: COSETypes.MAC,
    18: COSETypes.SIGN1,
    98: COSETypes.SIGN,
    19: COSETypes.COUNTERSIGNATURE,
}

COSE_TYPE_TO_TAG = {
    COSETypes.ENCRYPT0: 16,
    COSETypes.ENCRYPT: 96,
    COSETypes.MAC0: 17,
    COSETypes.MAC: 97,
    COSETypes.SIGN1: 18,
    COSETypes.SIGN: 98,
    COSETypes.COUNTERSIGNATURE: 19,
}

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
    "salt": -20,
    "alg": 1,
    "crit": 2,
    "cty": 3,
    "content type": 3,
    "kid": 4,
    "ek": -4,
    "psk_id": -5,
    "iv": 5,
    "IV": 5,
    "Partial IV": 6,
    "CounterSignature": 7,
    "CounterSignature0": 9,
    "kid context": 10,
    "CounterSignatureV2": 11,
    "CounterSignature0V2": 12,
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
    "wrapKey": 5,  # JWK
    "unwrap key": 6,
    "unwrapKey": 6,  # JWK
    "derive key": 7,
    "deriveKey": 7,  # JWK
    "derive bits": 8,
    "deriveBits": 8,  # JWK
    "MAC create": 9,
    "createMAC": 9,  # JWK-like lowerCamelCase
    "MAC verify": 10,
    "verifyMAC": 10,  # JWK-like lowerCamelCase
}


# COSE AEAD Algorithms
COSE_ALGORITHMS_CEK_AEAD = {
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

# COSE non AEAD Algorithms defined in RFC9459
COSE_ALGORITHMS_CEK_NON_AEAD = {
    "A128CTR": -65534,  # AES-CTR mode w/ 128-bit key (Deprecated)
    "A192CTR": -65533,  # AES-CTR mode w/ 192-bit key (Deprecated)
    "A256CTR": -65532,  # AES-CTR mode w/ 256-bit key (Deprecated)
    "A128CBC": -65531,  # AES-CBC mode w/ 128-bit key (Deprecated)
    "A192CBC": -65530,  # AES-CBC mode w/ 192-bit key (Deprecated)
    "A256CBC": -65529,  # AES-CBC mode w/ 256-bit key (Deprecated)
}

# COSE Algorithms for Content Encryption Key (CEK).
COSE_ALGORITHMS_CEK = {
    **COSE_ALGORITHMS_CEK_AEAD,
    **COSE_ALGORITHMS_CEK_NON_AEAD,
}

COSE_KEY_LEN = {
    -65534: 128,  # AES-CTR w/ 128-bit key (Deprecated)
    -65533: 192,  # AES-CTR w/ 192-bit key (Deprecated)
    -65532: 256,  # AES-CTR w/ 256-bit key (Deprecated)
    -65531: 128,  # AES-CBC w/ 128-bit key (Deprecated)
    -65530: 192,  # AES-CBC w/ 192-bit key (Deprecated)
    -65529: 256,  # AES-CBC w/ 256-bit key (Deprecated)
    -5: 256,  # AES Key Wrap w/ 256-bit key
    -4: 192,  # AES Key Wrap w/ 192-bit key
    -3: 128,  # AES Key Wrap w/ 128-bit key
    1: 128,  # AES-GCM mode w/ 128-bit key, 128-bit tag
    2: 192,  # AES-GCM mode w/ 192-bit key, 128-bit tag
    3: 256,  # AES-GCM mode w/ 256-bit key, 128-bit tag
    4: 64,  # HMAC w/ SHA-256 truncated to 64 bits
    5: 256,  # HMAC w/ SHA-256
    6: 384,  # HMAC w/ SHA-384
    7: 512,  # HMAC w/ SHA-512
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
    "dir": -6,  # direct (JWK)
    # etc.
}

COSE_ALGORITHMS_KEY_WRAP = {
    "A256KW": -5,  # AES Key Wrap w/ 256-bit key
    "A192KW": -4,  # AES Key Wrap w/ 192-bit key
    "A128KW": -3,  # AES Key Wrap w/ 128-bit key
    # etc.
}

COSE_ALGORITHMS_HPKE = {
    # New names per draft-ietf-cose-hpke-15
    "HPKE-0": 35,  # DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
    "HPKE-1": 37,  # DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM
    "HPKE-2": 39,  # DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM
    "HPKE-3": 41,  # DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
    "HPKE-4": 42,  # DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305
    "HPKE-5": 43,  # DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM
    "HPKE-6": 44,  # DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + ChaCha20Poly1305
    # Backward-compatible legacy names
    "HPKE-Base-P256-SHA256-AES128GCM": 35,
    "HPKE-Base-P256-SHA256-ChaCha20Poly1305": 36,
    "HPKE-Base-P384-SHA384-AES256GCM": 37,
    "HPKE-Base-P384-SHA384-ChaCha20Poly1305": 38,
    "HPKE-Base-P521-SHA512-AES256GCM": 39,
    "HPKE-Base-P521-SHA512-ChaCha20Poly1305": 40,
    "HPKE-Base-X448-SHA512-AES256GCM": 43,
    "HPKE-Base-X448-SHA512-ChaCha20Poly1305": 44,
    "HPKE-Base-X25519-SHA256-AES128GCM": 41,
    "HPKE-Base-X25519-SHA256-ChaCha20Poly1305": 42,
}

COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_SS = {
    "ECDH-SS+A256KW": -34,  # ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
    "ECDH-SS+A192KW": -33,  # ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
    "ECDH-SS+A128KW": -32,  # ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
    # etc.
}

COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_ES = {
    "ECDH-ES+A256KW": -31,  # ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
    "ECDH-ES+A192KW": -30,  # ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
    "ECDH-ES+A128KW": -29,  # ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
    # etc.
}

COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_SS = {
    "ECDH-SS+HKDF-512": -28,  # ECDH SS w/ HKDF - generate key directly
    "ECDH-SS+HKDF-256": -27,  # ECDH SS w/ HKDF - generate key directly
    # etc.
}

COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_ES = {
    "ECDH-ES+HKDF-512": -26,  # ECDH ES w/ HKDF - generate key directly
    "ECDH-ES+HKDF-256": -25,  # ECDH ES w/ HKDF - generate key directly
    # etc.
}

# COSE Algorithms for MAC.
COSE_ALGORITHMS_MAC = {
    "HMAC 256/64": 4,  # HMAC w/ SHA-256 truncated to 64 bits
    "HMAC 256/256": 5,  # HMAC w/ SHA-256
    "HS256": 5,  # HMAC w/ SHA-256 (JWK)
    "HMAC 384/384": 6,  # HMAC w/ SHA-384
    "HS384": 6,  # HMAC w/ SHA-384 (JWK)
    "HMAC 512/512": 7,  # HMAC w/ SHA-512
    "HS512": 7,  # HMAC w/ SHA-512 (JWK)
    "AES-MAC128/64": 14,  # AES-MAC 128-bit key, 64-bit tag
    "AES-MAC256/64": 15,  # AES-MAC 256-bit key, 64-bit tag
    "AES-MAC128/128": 25,  # AES-MAC 128-bit key, 128-bit tag
    "AES-MAC256/128": 26,  # AES-MAC 256-bit key, 128-bit tag
    # etc.
}

# COSE Algorithms for Signature with OKP.
COSE_ALGORITHMS_SIG_OKP = {
    "EdDSA": -8,  # EdDSA
    "Ed25519": -19,  # EdDSA using Ed25519 curve
    "Ed448": -53,  # EdDSA using Ed448 curve
}

# COSE Algorithms for Signature with EC2.
COSE_ALGORITHMS_SIG_EC2 = {
    "ESP512": -52,  # ECDSA using P-521 curve and SHA-512
    "ESP384": -51,  # ECDSA using P-384 curve and SHA-384
    "ES256K": -47,  # ECDSA using secp256k1 curve and SHA-256
    "ES512": -36,  # ECDSA w/ SHA-512 (any curve is not specified but python-cwt uses P-521 curve)
    "ES384": -35,  # ECDSA w/ SHA-384 (any curve is not specified but python-cwt uses P-384 curve)
    "ESP256": -9,  # ECDSA using P-256 curve and SHA-256
    "ES256": -7,  # ECDSA w/ SHA-256 (any curve is not specified but python-cwt uses P-256 curve)
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

# COSE Algorithms for CKDM Direct Key Agreement.
COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT = {
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_SS,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_ES,
}

# COSE Algorithms for CKDM Key Agreement with Key Wrap.
COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP = {
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_SS,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_ES,
}

# COSE Algorithms for CKDM Key Agreement (Static-Static).
COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_SS = {
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_SS,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_SS,
}

# COSE Algorithms for CKDM Key Agreement (Ephemeral-Static).
COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_ES = {
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT_ES,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP_ES,
}

# COSE Algorithms for CKDM Key Agreement.
COSE_ALGORITHMS_CKDM_KEY_AGREEMENT = {
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_DIRECT,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT_WITH_KEY_WRAP,
}

# COSE Algorithms for recipients.
COSE_ALGORITHMS_RECIPIENT = {
    **COSE_ALGORITHMS_CKDM,
    **COSE_ALGORITHMS_KEY_WRAP,
    **COSE_ALGORITHMS_CKDM_KEY_AGREEMENT,
    **COSE_ALGORITHMS_HPKE,
}

# COSE Algorithms for Symmetric Keys.
COSE_ALGORITHMS_SYMMETRIC = {
    **COSE_ALGORITHMS_MAC,
    **COSE_ALGORITHMS_CEK,
    **COSE_ALGORITHMS_KEY_WRAP,
}

# COSE Algorithms for RSA Keys.
COSE_ALGORITHMS_RSA = {**COSE_ALGORITHMS_SIG_RSA}

# COSE Algorithms for RSA Keys.
COSE_ALGORITHMS_SIGNATURE = {
    **COSE_ALGORITHMS_SIG_OKP,
    **COSE_ALGORITHMS_SIG_EC2,
    **COSE_ALGORITHMS_SIG_RSA,
}

# All of Supported COSE Algorithms.
COSE_ALGORITHMS = {
    **COSE_ALGORITHMS_SIGNATURE,
    **COSE_ALGORITHMS_SYMMETRIC,
    **COSE_ALGORITHMS_RECIPIENT,
}

# COSE Named Algorithms for converting from JWK-like key.
COSE_NAMED_ALGORITHMS_SUPPORTED = {**JOSE_ALGORITHMS_SUPPORTED, **COSE_ALGORITHMS}
