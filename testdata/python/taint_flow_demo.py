# taint_flow_demo.py
# Skenario: Source (input user) → Sink (cursor.execute)

def get_user_input():
    # SOURCE: data dari user
    user_id = input("Enter user ID: ")
    return user_id

def process_user_id(user_input):
    # Proses data
    query = "SELECT * FROM users WHERE id = " + user_input
    return query

def execute_query(query):
    # SINK: eksekusi query
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)  # <-- SINK (SQL Injection)
    return cursor.fetchone()

def main():
    # Alur: source → sink
    user_id = get_user_input()      # Source
    query = process_user_id(user_id) # Assignment
    result = execute_query(query)    # Sink

if __name__ == "__main__":
    main()