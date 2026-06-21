"""KB SanitizerSpec test_fixture — sanitizer candidate 예시(충분성은 S3 LLM 판정)."""
import shlex
import subprocess
import yaml


def shell_escaped(cmd: str):
    return subprocess.run(shlex.quote(cmd), shell=True)   # shlex.quote (shell_escape)


def parameterized(cur, name: str):
    return cur.execute("SELECT * FROM u WHERE n=?", (name,))  # parameterization


def safe_yaml(s: str):
    return yaml.safe_load(s)                               # yaml.safe_load (safe_api)


def validate_prefix(name: str):
    assert name.startswith("ok-")                          # validate_* (name-only candidate)
    return name
