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
    HPKE_SENDER_INFO = -4
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
