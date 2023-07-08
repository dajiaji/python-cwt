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
