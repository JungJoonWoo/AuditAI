import pickle
from fastapi import FastAPI
app = FastAPI()


@app.get('/d')
def deser(b: str):
    return pickle.loads(b.encode())  # CWE-502
