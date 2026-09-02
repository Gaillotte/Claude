import sqlite3
def lookup(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
