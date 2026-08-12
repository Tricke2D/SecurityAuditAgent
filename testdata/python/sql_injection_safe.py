import sqlite3

def get_user_by_id_safe(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ SAFE: Parameterized query (query terpisah dari data)
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    return cursor.fetchone()

def search_users_safe(keyword):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ SAFE: Parameterized query
    query = "SELECT * FROM users WHERE name LIKE ?"
    cursor.execute(query, (f"%{keyword}%",))

    return cursor.fetchall()