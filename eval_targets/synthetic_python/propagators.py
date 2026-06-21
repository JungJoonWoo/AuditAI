"""KB PropagatorSpec test_fixture — taint 전파 wrapper 예시."""
import os


def build_query(name: str) -> str:
    return "SELECT * FROM u WHERE n='{}'".format(name)     # str.format (string_build)


def build_path(base: str, user: str) -> str:
    return os.path.join(base, user)                        # os.path.join (path_build)
