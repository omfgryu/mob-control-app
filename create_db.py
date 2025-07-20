import sqlite3

# This will create a new database named players.db in the current folder
conn = sqlite3.connect("players.db")
cursor = conn.cursor()

# Create the players table with all required fields
cursor.execute('''
CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    country TEXT NOT NULL,
    tier TEXT NOT NULL,
    registered_at TEXT NOT NULL
)
''')

conn.commit()
conn.close()

print("✅ Database 'players.db' created with correct 'players' table.")
