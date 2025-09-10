import datetime
import os
from calendar import timegm


def now() -> int:
    if hasattr(datetime, "UTC"):
        # 3.11 and up has datetime.UTC, and deprecates datetime.datetime.utcnow()
        return timegm(datetime.datetime.now(datetime.UTC).utctimetuple())
    else:
        return timegm(datetime.datetime.utcnow().utctimetuple())


def key_path(key_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)
