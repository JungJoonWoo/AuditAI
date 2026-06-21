from fastapi import FastAPI
app = FastAPI()


@app.get('/p')
def path(fn: str):
    return open(fn).read()  # CWE-22
