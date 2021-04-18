class CWTError(Exception):
    """
    Base class for all exceptions.
    """

    pass


class VerifyError(CWTError):
    """
    An Exception occurred when a verification process failed.
    """

    pass


class EncodeError(CWTError):
    """
    An Exception occurred when a CWT/COSE encoding process failed.
    """

    pass


class DecodeError(CWTError):
    """
    An Exception occurred when a CWT/COSE decoding process failed.
    """

    pass
