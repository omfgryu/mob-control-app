import sqlite3

conn = sqlite3.connect("players.db")
c = conn.cursor()

c.execute("SELECT id, name, country, tier, registered_at, social_links FROM players ORDER BY registered_at DESC")
rows = c.fetchall()

for row in rows:
    print(f"ID: {row[0]}")
    print(f"Name: {row[1]}")
    print(f"Country: {row[2]}")
    print(f"Tier: {row[3]}")
    print(f"Registered: {row[4]}")
    print(f"Social: {row[5]}")
    print("-" * 30)

conn.close()
