# vulnerable_query.py
# Skenario: SQL Injection tanpa sanitasi

def get_user_data(request):
    # SOURCE: input dari user
    user_id = request.GET.get("id")
    
    # Tidak ada sanitasi/validasi
    query = "SELECT * FROM users WHERE id = " + user_id
    
    # SINK: eksekusi query langsung
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    
    return cursor.fetchall()