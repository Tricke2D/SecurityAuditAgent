import sqlite3

def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: String concatenation langsung ke query
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)

    return cursor.fetchone()

def search_users(keyword):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: f-string langsung ke query
    query = f"SELECT * FROM users WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)

    return cursor.fetchall()