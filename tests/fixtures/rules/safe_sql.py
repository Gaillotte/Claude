import sqlite3
def lookup(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
def insert(conn, a, b):
    conn.executemany("INSERT INTO t VALUES (?, ?)", [(a, b)])
