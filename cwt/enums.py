import enum


class COSETypes(enum.IntEnum):
    ENCRYPT0 = 1
    ENCRYPT = 2
    MAC0 = 3
    MAC = 4
    SIGN1 = 5
    SIGN = 6
    COUNTERSIGNATURE = 7
    RECIPIENT = 8
    SIGNATURE = 9


class COSEHeaders(enum.IntEnum):
    ALG = 1
    CRIT = 2
    CTY = 3
    KID = 4
    IV = 5
    PARTIAL_IV = 6
    COUNTER_SIGNATURE = 7
    COUNTER_SIGNATURE_0 = 9
    KID_CONTEXT = 10
    COUNTER_SIGNATURE_V2 = 11
    COUNTER_SIGNATURE_0_V2 = 12
    CWT_CLAIMS = 13
    X5BAG = 32
    X5CHAIN = 33
    X5T = 34
    X5U = 35
    CUPH_NONCE = 256
    CUPH_OWNER_PUB_KEY = 257


class COSEKeyParams(enum.IntEnum):
    KTY = 1
    KID = 2
    ALG = 3
    KEY_OPS = 4
    BASE_IV = 5
    CRV = -1
    X = -2
    Y = -3
    D = -4
    RSA_N = -1
    RSA_E = -2
    RSA_D = -3
    RSA_P = -4
    RSA_Q = -5
    RSA_DP = -6
    RSA_DQ = -7
    RSA_QINV = -8
    RSA_OTHER = -9
    RSA_R_I = -10
    RsA_D_I = -11
    RSA_T_I = -12
    K = -1


class COSEAlgs(enum.IntEnum):
    A128CTR = -65534
    A192CTR = -65533
    A256CTR = -65532
    A128CBC = -65531
    A192CBC = -65530
    A256CBC = -65529
    RS512 = -259
    RS384 = -258
    RS256 = -257
    ES256K = -47
    PS512 = -39
    PS384 = -38
    PS256 = -37
    ES512 = -36
    ES384 = -35
    ECDH_SS_A256KW = -34
    ECDH_SS_A192KW = -33
    ECDH_SS_A128KW = -32
    ECDH_ES_A256KW = -31
    ECDH_ES_A192KW = -30
    ECDH_ES_A128KW = -29
    ECDH_SS_HKDF_512 = -28
    ECDH_SS_HKDF_256 = -27
    ECDH_ES_HKDF_512 = -26
    ECDH_ES_HKDF_256 = -25
    DIRECT_HKDF_SHA512 = -11
    DIRECT_HKDF_SHA256 = -10
    EDDSA = -8
    ES256 = -7
    DIRECT = -6
    A256KW = -5
    A192KW = -4
    A128KW = -3
    A128GCM = 1
    A192GCM = 2
    A256GCM = 3
    HS256_64 = 4
    HS256 = 5
    HS384 = 6
    HS512 = 7
    AES_CCM_16_64_128 = 10
    AES_CCM_16_64_256 = 11
    AES_CCM_64_64_128 = 12
    AES_CCM_64_64_256 = 13
    CHACHA20_POLY1305 = 24
    AES_CCM_16_128_128 = 30
    AES_CCM_16_128_256 = 31
    AES_CCM_64_128_128 = 32
    AES_CCM_64_128_256 = 33
    HPKE_BASE_P256_SHA256_AES128GCM = 35
    HPKE_BASE_P256_SHA256_CHACHA20POLY1305 = 36
    HPKE_BASE_P384_SHA384_AES256GCM = 37
    HPKE_BASE_P384_SHA384_CHACHA20POLY1305 = 38
    HPKE_BASE_P521_SHA512_AES256GCM = 39
    HPKE_BASE_P521_SHA512_CHACHA20POLY1305 = 40
    HPKE_BASE_X25519_SHA256_AES128GCM = 41
    HPKE_BASE_X25519_SHA256_CHACHA20POLY1305 = 42
    HPKE_BASE_X448_SHA512_AES256GCM = 43
    HPKE_BASE_X448_SHA512_CHACHA20POLY1305 = 44


class CWTClaims(enum.IntEnum):
    HCERT = -260
    EUPH_NONCE = -259
    EAT_MAROE_PREFIX = -258
    EAT_FDO = -257
    ISS = 1
    SUB = 2
    AUD = 3
    EXP = 4
    NBF = 5
    IAT = 6
    CTI = 7
    CNF = 8
    NONCE = 10
    UEID = 11
    OEMID = 13
    SEC_LEVEL = 14
    SEC_BOOT = 15
    DBG_STAT = 16
    LOCATION = 17
    EAT_PROFILE = 18
    SUBMODS = 20


class COSEKeyTypes(enum.IntEnum):
    OKP = 1
    EC2 = 2
    RSA = 3
    ASYMMETRIC = 4
    # HSS_LMS = 5
    # WALNUT_DSA = 6


class COSEKeyCrvs(enum.IntEnum):
    P256 = 1
    P384 = 2
    P521 = 3
    X25519 = 4
    X448 = 5
    ED25519 = 6
    ED448 = 7
    SECP256K1 = 8


class COSEKeyOps(enum.IntEnum):
    SIGN = 1
    VERIFY = 2
    ENCRYPT = 3
    DECRYPT = 4
    WRAP_KEY = 5
    UNWRAP_KEY = 6
    DERIVE_KEY = 7
    DERIVE_BITS = 8
    MAC_CREATE = 9
    MAC_VERIFY = 10
