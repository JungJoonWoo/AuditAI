# 의도적 취약: FastAPI query param(source) → subprocess(sink). CWE-78.
from fastapi import FastAPI
import subprocess

app = FastAPI()


@app.get("/run")
def run(cmd: str):  # source: user-controlled query param
    return subprocess.run(cmd, shell=True)  # sink: command execution
