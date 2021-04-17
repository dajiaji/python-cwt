import os


def key_path(key_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)
