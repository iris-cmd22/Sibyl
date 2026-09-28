import sqlite3

_DB = "app.db"


def get_connection():
    return sqlite3.connect(_DB)


def get_user(uid):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT name, email FROM users WHERE id = " + uid
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return str(row)
