import sqlite3

DB_PATH = "players.db"  # adjust if your DB path is different

def reset_players():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM players")  # deletes all rows
    conn.commit()
    conn.close()
    print("All registered players have been deleted/reset.")

if __name__ == "__main__":
    reset_players()
