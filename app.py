# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime, timezone
import pytz
from geopy.geocoders import Nominatim
from timezonefinder import TimezoneFinder
import json
import os
import sqlite3
import re


from flask import request
from collections import defaultdict
import time

# Simple in-memory dictionary to track timestamps of registrations per IP
ip_timestamps = defaultdict(list)

# Limits
MAX_ATTEMPTS = 3
WINDOW_SECONDS = 600  # 10 minutes

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change to your own secret key in production

# Load countries list from countries.json file at startup
with open(os.path.join(os.path.dirname(__file__), "countries.json"), "r", encoding="utf-8") as f:
    countries = json.load(f)

# Official Mob Control Tier Rank List
tiers = [
    "Wood", "Iron", "Bronze", "Silver", "Gold", "Platinum",
    "Diamond", "Master", "Grandmaster", "Immortal",
    "Fabled", "Exalted", "Divine", "Celestial",
    "Blessed", "Astral", "Seraphic", "God"
]

DB_PATH = os.path.join(os.path.dirname(__file__), "players.db")

def init_db():
    """Create players table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
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

init_db()
def init_ping_db():
    """Create ping_notifications table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ping_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_name TEXT NOT NULL,
            sender_country TEXT NOT NULL,
            sender_local_time TEXT NOT NULL,
            receiver_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_ping_db()


def sanitize_input(text):
    """
    Allow letters, numbers, spaces, underscores, hyphens, dots, and dollar signs.
    Disallow emojis and other special symbols.
    """
    allowed_chars_pattern = r'[^a-zA-Z0-9 _\-\.\$]'
    return re.sub(allowed_chars_pattern, '', text)

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get client IP address
        ip = request.remote_addr
        now = time.time()
        ip_timestamps[ip] = [ts for ts in ip_timestamps[ip] if now - ts < WINDOW_SECONDS]

        if len(ip_timestamps[ip]) >= MAX_ATTEMPTS:
            flash("Too many attempts. Please wait before trying again.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        ip_timestamps[ip].append(now)
        # Honeypot spam check - this field should be empty for real users
        honeypot = request.form.get("email_confirm", "")
        if honeypot:
            flash("Spam detected. Submission rejected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        name = sanitize_input(request.form.get("name", "").strip())
        country = request.form.get("country", "").strip()
        tier = request.form.get("tier", "").strip()

        # Validate fields are not empty
        if not name or not country or not tier:
            flash("Please fill in all required fields.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        # Validate country and tier against official lists (prevent fake entries)
        if country not in countries or tier not in tiers:
            flash("Invalid country or rank tier selected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        # **Check if username already exists**
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM players WHERE name = ?", (name,))
        exists = c.fetchone()[0]
        conn.close()

        if exists > 0:
            flash(f"Username '{name}' is already registered. Please choose another username.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        # Save registration time as timezone-aware UTC ISO string
        registered_at = datetime.now(timezone.utc).isoformat()

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO players (name, country, tier, registered_at) VALUES (?, ?, ?, ?)",
                      (name, country, tier, registered_at))
            conn.commit()
            conn.close()

            flash(f"Player '{name}' registered successfully!", "success")
            return redirect(url_for("register"))

        except Exception as e:
            flash(f"Database error: {e}", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

    # GET request
    return render_template("register.html", countries=countries, tiers=tiers)


@app.route("/players", methods=["GET"])
def players():
    """Show a list of registered players with optional search filters."""
    search_name = request.args.get("name", "").strip()
    search_country = request.args.get("country", "").strip()
    search_tier = request.args.get("tier", "").strip()

    query = "SELECT id, name, country, tier, registered_at FROM players WHERE 1=1"
    params = []

    # Add filters if present
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

    return render_template("players.html",
                           players=players_list,
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
            location = geolocator.geocode(f"{country}, country")
        if not location:
            return jsonify({"time": "Unknown", "timezone": None}), 404

        tf = TimezoneFinder()
        tz_name = tf.timezone_at(lat=location.latitude, lng=location.longitude)

        if not tz_name:
            return jsonify({"time": "Unknown", "timezone": None}), 404

        tz = pytz.timezone(tz_name)
        now = datetime.now(tz)
        local_time_str = now.strftime("%H:%M:%S")

        return jsonify({"time": local_time_str, "timezone": tz_name})

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
    # Get sender's info from form (or IP) – we simulate logged-in user using "name" for now
    sender_name = request.form.get("sender_name", "").strip()
    if not sender_name:
        return "Missing sender name", 400

    # Fetch sender's country from DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT country FROM players WHERE name = ?", (sender_name,))
    result = c.fetchone()
    if not result:
        conn.close()
        return "Sender not found", 404

    sender_country = result[0]
    conn.close()

    # Get local time for sender
    try:
        geolocator = Nominatim(user_agent="mob_control_app")
        location = geolocator.geocode(sender_country)
        tf = TimezoneFinder()
        tz_name = tf.timezone_at(lat=location.latitude, lng=location.longitude)
        tz = pytz.timezone(tz_name)
        local_time = datetime.now(tz).strftime("%H:%M:%S")
    except:
        local_time = "Unknown"

    timestamp = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO ping_notifications (sender_name, sender_country, sender_local_time, receiver_id, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (sender_name, sender_country, local_time, player_id, timestamp))
    conn.commit()
    conn.close()

    return '', 204

@app.route("/profile/<player_name>")
def profile(player_name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Fetch player's own info
    c.execute("SELECT id, name, country, tier, registered_at FROM players WHERE name = ?", (player_name,))
    player = c.fetchone()

    if not player:
        conn.close()
        flash("Player not found.", "error")
        return redirect(url_for("players"))

    # Fetch all pings where this player is the receiver
    c.execute("SELECT sender_name, sender_country, sender_local_time, timestamp FROM ping_notifications WHERE receiver_id = ?", (player[0],))
    pings = c.fetchall()

    conn.close()

    return render_template("profile.html", player=player, pings=pings)


if __name__ == "__main__":
    app.run(debug=True)
