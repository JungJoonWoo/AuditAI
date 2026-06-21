def handler(cursor, name):
    cursor.execute(f"SELECT * FROM u WHERE n='{name}'")  # CWE-89 TP
def safe(cursor, name):
    cursor.execute("SELECT * FROM u WHERE n=%s", (name,))  # parameterized: TN
