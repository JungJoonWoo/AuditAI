import sqlite3
from fastapi import FastAPI
app = FastAPI()


@app.get('/s')
def sql(name: str):
    cur = sqlite3.connect('db').cursor()
    return cur.execute(f"SELECT * FROM u WHERE n='{name}'")  # CWE-89
