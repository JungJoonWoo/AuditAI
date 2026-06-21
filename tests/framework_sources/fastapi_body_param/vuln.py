# 의도적 취약: FastAPI body param(source) → eval(sink). CWE-94.
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class In(BaseModel):
    expr: str


@app.post("/calc")
def calc(payload: In):  # source: request body field
    return eval(payload.expr)  # sink: code execution
