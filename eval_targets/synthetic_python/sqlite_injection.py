import sqlite3
import aiosqlite
def cur_exec(cursor, name):
    cursor.execute(f"SELECT * FROM u WHERE n='{name}'")          # CWE-89 TP (sqlite3.Cursor.execute)
def cur_script(cursor, body):
    cursor.executescript(f"INSERT INTO logs VALUES ('{body}')")  # CWE-89 TP (sqlite3.Cursor.executescript)
def conn_exec(conn, name):
    conn.execute(f"SELECT * FROM u WHERE n='{name}'")            # CWE-89 TP (sqlite3.Connection.execute)
def conn_script(conn, body):
    conn.executescript(f"INSERT INTO logs VALUES ('{body}')")    # CWE-89 TP (sqlite3.Connection.executescript)
async def aio_cur_exec(cursor, name):
    await cursor.execute(f"SELECT * FROM u WHERE n='{name}'")    # CWE-89 TP (aiosqlite.Cursor.execute)
async def aio_conn_exec(conn, name):
    await conn.execute(f"SELECT * FROM u WHERE n='{name}'")      # CWE-89 TP (aiosqlite.Connection.execute)
def safe(cursor, name):
    cursor.execute("SELECT * FROM u WHERE n=?", (name,))         # parameterized: TN
