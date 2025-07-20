from flask import Flask, render_template, request, redirect, url_for, g
import sqlite3
from datetime import datetime
import pytz

app = Flask(__name__)
DATABASE = "players.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            region TEXT NOT NULL,
            timezone TEXT NOT NULL,
            tier TEXT NOT NULL,
            social TEXT
        )""")
        db.commit()

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        region = request.form["region"]
        timezone = request.form["timezone"]
        tier = request.form["tier"]
        social = request.form["social"]

        db = get_db()
        db.execute("INSERT INTO players (username, region, timezone, tier, social) VALUES (?, ?, ?, ?, ?)",
                   (username, region, timezone, tier, social))
        db.commit()
        return redirect(url_for("players"))
    return render_template("register.html")

@app.route("/players")
def players():
    db = get_db()
    players = db.execute("SELECT * FROM players").fetchall()
    return render_template("players.html", players=players)

@app.route("/profile/<int:player_id>")
def profile(player_id):
    db = get_db()
    player = db.execute("SELECT * FROM players WHERE id = ?", (player_id,)).fetchone()

    if player:
        # Convert UTC to local time using timezone field
        try:
            tz = pytz.timezone(player[3])
            now_local = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            now_local = "Invalid timezone"
    else:
        now_local = "Unknown"

    return render_template("profile.html", player=player, local_time=now_local)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
