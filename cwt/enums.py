import enum


class COSEType(enum.IntEnum):
    ENCRYPT0 = 1
    ENCRYPT = 2
    MAC0 = 3
    MAC = 4
    SIGN1 = 5
    SIGN = 6
    COUNTERSIGNATURE = 7
    RECIPIENT = 8
    SIGNATURE = 9
