import sqlite3

DB_PATH = "players.db"  # Use your existing DB path

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Create blocks table
c.execute("""
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    UNIQUE(blocker_id, blocked_id)
);
""")

# Create pings table
c.execute("""
CREATE TABLE IF NOT EXISTS pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
""")

conn.commit()
conn.close()
print("Database updated with 'blocks' and 'pings' tables.")
