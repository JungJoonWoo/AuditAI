from fastapi import FastAPI
app = FastAPI()


@app.get('/e')
def ce(x: str):
    return eval(x)  # CWE-94
