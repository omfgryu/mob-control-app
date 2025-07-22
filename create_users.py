# create_users.py

import sqlite3
from werkzeug.security import generate_password_hash

# Connect to users.db (or create if doesn't exist)
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'player'))
    )
''')

# Insert default admin (username: admin, password: mobgod123)
admin_username = 'amrit'
admin_password = generate_password_hash('gogetassj4')  # hashed password
admin_role = 'admin'

try:
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   (admin_username, admin_password, admin_role))
    print("[✅] Admin user created.")
except sqlite3.IntegrityError:
    print("[ℹ️] Admin user already exists.")

conn.commit()
conn.close()
