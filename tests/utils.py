import os
from calendar import timegm
from datetime import UTC, datetime


def now() -> int:
    return timegm(datetime.now(UTC).utctimetuple())


def key_path(key_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)
