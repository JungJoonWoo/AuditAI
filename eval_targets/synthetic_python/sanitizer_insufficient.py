def handler(cursor, name):
    safe = name.replace("'", "")  # name-only sanitize, insufficient
    cursor.execute(f"SELECT * FROM u WHERE n='{safe}'")  # still SQLi
