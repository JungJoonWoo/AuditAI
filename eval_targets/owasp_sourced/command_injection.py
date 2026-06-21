import subprocess
from fastapi import FastAPI
app = FastAPI()


@app.get('/c')
def cmd(i: str):
    return subprocess.run(i, shell=True)  # CWE-78 (source=route param, sink=shell)
