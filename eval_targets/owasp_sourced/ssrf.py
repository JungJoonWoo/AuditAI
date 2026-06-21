import requests
from fastapi import FastAPI
app = FastAPI()


@app.get('/u')
def ssrf(url: str):
    return requests.get(url).text  # CWE-918
