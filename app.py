# app.py (updated with working socials support)
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime, timezone
import pytz
from geopy.geocoders import Nominatim
from timezonefinder import TimezoneFinder
import json
import os
import sqlite3
import re
from collections import defaultdict
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"

ip_timestamps = defaultdict(list)
MAX_ATTEMPTS = 3
WINDOW_SECONDS = 600  # 10 minutes

# Load countries list from countries.json file
with open(os.path.join(os.path.dirname(__file__), "countries.json"), "r", encoding="utf-8") as f:
    countries = json.load(f)

tiers = [
    "Wood", "Iron", "Bronze", "Silver", "Gold", "Platinum",
    "Diamond", "Master", "Grandmaster", "Immortal",
    "Fabled", "Exalted", "Divine", "Celestial",
    "Blessed", "Astral", "Seraphic", "God"
]

DB_PATH = os.path.join(os.path.dirname(__file__), "players.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            country TEXT NOT NULL,
            tier TEXT NOT NULL,
            registered_at TEXT NOT NULL,
            social_links TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Ensure social_links column exists
init_db()
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("PRAGMA table_info(players)")
columns = [col[1] for col in c.fetchall()]
if "social_links" not in columns:
    c.execute("ALTER TABLE players ADD COLUMN social_links TEXT")
conn.commit()
conn.close()

def sanitize_input(text):
    return re.sub(r'[^a-zA-Z0-9 _\-\.\$]', '', text)

# ✅ Home route added
@app.route('/')
def home():
    return '''
    <h2 style="text-align:center; font-family:sans-serif;">
        🧠 Mob Control App<br>Player Matchmaking Tool
    </h2>
    <p style="text-align:center;">
        <a href="/register">Register</a> | <a href="/players">View Players</a>
    </p>
    '''

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        ip = request.remote_addr
        now = time.time()
        ip_timestamps[ip] = [ts for ts in ip_timestamps[ip] if now - ts < WINDOW_SECONDS]

        if len(ip_timestamps[ip]) >= MAX_ATTEMPTS:
            flash("Too many attempts. Please wait before trying again.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        ip_timestamps[ip].append(now)
        honeypot = request.form.get("email_confirm", "")
        if honeypot:
            flash("Spam detected. Submission rejected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        name = sanitize_input(request.form.get("name", "").strip())
        country = request.form.get("country", "").strip()
        tier = request.form.get("tier", "").strip()
        social_links = sanitize_input(request.form.get("social_links", "").strip())

        if not name or not country or not tier:
            flash("Please fill in all required fields.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        if country not in countries or tier not in tiers:
            flash("Invalid country or rank tier selected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM players WHERE name = ?", (name,))
        exists = c.fetchone()[0]
        conn.close()

        if exists > 0:
            flash(f"Username '{name}' is already registered.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        registered_at = datetime.now(timezone.utc).isoformat()

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO players (name, country, tier, registered_at, social_links) VALUES (?, ?, ?, ?, ?)",
                      (name, country, tier, registered_at, social_links))
            conn.commit()
            conn.close()

            flash(f"Player '{name}' registered successfully!", "success")
            return redirect(url_for("players"))  # 👈 Redirect to players page

        except Exception as e:
            flash(f"Database error: {e}", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

    return render_template("register.html", countries=countries, tiers=tiers)

@app.route("/players", methods=["GET"])
def players():
    search_name = request.args.get("name", "").strip()
    search_country = request.args.get("country", "").strip()
    search_tier = request.args.get("tier", "").strip()

    query = "SELECT id, name, country, tier, registered_at, social_links FROM players WHERE 1=1"
    params = []

    if search_name:
        query += " AND name LIKE ?"
        params.append(f"%{search_name}%")
    if search_country and search_country in countries:
        query += " AND country = ?"
        params.append(search_country)
    if search_tier and search_tier in tiers:
        query += " AND tier = ?"
        params.append(search_tier)

    query += " ORDER BY registered_at DESC"

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    players_list = c.fetchall()
    conn.close()

    # Add local time conversion to each player row
    players_with_local_time = []
    for player in players_list:
        local_time = get_local_time_for_country(player[2])  # player[2] = country
        players_with_local_time.append(player + (local_time,))

    return render_template("players.html",
                           players=players_with_local_time,
                           countries=countries,
                           tiers=tiers,
                           search_name=search_name,
                           search_country=search_country,
                           search_tier=search_tier)

@app.route("/get_time", methods=["POST"])
def get_time():
    data = request.get_json()
    country = data.get("country")

    if not country:
        return jsonify({"time": "Unknown", "timezone": None}), 400

    try:
        geolocator = Nominatim(user_agent="mob_control_app")
        location = geolocator.geocode(country)
        if not location:
            return jsonify({"time": "Unknown", "timezone": None}), 404

        tf = TimezoneFinder()
        tz_name = tf.timezone_at(lat=location.latitude, lng=location.longitude)

        if not tz_name:
            return jsonify({"time": "Unknown", "timezone": None}), 404

        tz = pytz.timezone(tz_name)
        now = datetime.now(tz)
        return jsonify({"time": now.strftime("%H:%M:%S"), "timezone": tz_name})

    except Exception as e:
        print(f"Error in /get_time: {e}")
        return jsonify({"time": "Error", "timezone": None}), 500

@app.route("/delete_player/<int:player_id>", methods=["POST"])
def delete_player(player_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM players WHERE id = ?", (player_id,))
        conn.commit()
        conn.close()
        flash("Player deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting player: {e}", "error")

    return redirect(url_for("players"))

@app.route('/ping/<int:player_id>', methods=['POST'])
def ping_player(player_id):
    return '', 204

# 🆕 Helper function added to get local time based on country
def get_local_time_for_country(country_name):
    try:
        geolocator = Nominatim(user_agent="mob_control_app")
        location = geolocator.geocode(country_name)
        if not location:
            return "N/A"
        tf = TimezoneFinder()
        tz_name = tf.timezone_at(lat=location.latitude, lng=location.longitude)
        if not tz_name:
            return "N/A"
        tz = pytz.timezone(tz_name)
        local_time = datetime.now(tz)
        return local_time.strftime("%H:%M")
    except:
        return "N/A"

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))  # Use Render's provided PORT
    app.run(host="0.0.0.0", port=port)
