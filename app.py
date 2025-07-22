# app.py
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import session, Flask, render_template, request, jsonify, redirect, url_for, flash, g
from datetime import datetime, timezone
import pytz
from geopy.geocoders import Nominatim
from timezonefinder import TimezoneFinder
import json
import os
import psycopg2
import bcrypt
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import re
from collections import defaultdict
import time
from functools import lru_cache

app = Flask(__name__)
csrf = CSRFProtect(app)

# Add after_request decorator to the app
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

app.config['DEBUG'] = True
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable is required")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# Move admin credentials to environment variables for security
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'omfgryu')
ADMIN_PIN = os.environ.get('ADMIN_PIN', 'gogetassj4')

#ip_timestamps = defaultdict(list)
#MAX_ATTEMPTS = 3
#WINDOW_SECONDS = 600

with open(os.path.join(os.path.dirname(__file__), "countries.json"), "r", encoding="utf-8") as f:
    countries = json.load(f)

tiers = [
    "Wood", "Iron", "Bronze", "Silver", "Gold", "Platinum",
    "Diamond", "Master", "Grandmaster", "Immortal",
    "Fabled", "Exalted", "Divine", "Celestial",
    "Blessed", "Astral", "Seraphic", "God"
]

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

try:
    connection_pool = psycopg2.pool.ThreadedConnectionPool(1, 20, DATABASE_URL)
except Exception as e:
    print(f"Error creating connection pool: {e}")
    connection_pool = None

geolocator = Nominatim(user_agent="mob_control_app", timeout=5)
tz_finder = TimezoneFinder()

def get_db_connection():
    """Helper function to get a fresh database connection"""
    return psycopg2.connect(DATABASE_URL)

def get_user_pings(user_id):
    """Get unread pings for a user with sender details"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT p.id, p.timestamp, u.name as username, u.country, u.tier, p.sender_id
            FROM pings p
            JOIN players u ON p.sender_id = u.id
            WHERE p.receiver_id = %s AND p.is_read = FALSE
            ORDER BY p.timestamp DESC
        """, (user_id,))
        
        pings = cur.fetchall()
        cur.close()
        conn.close()
        
        # Add local time for each ping
        for ping in pings:
            ping['local_time'] = get_local_time_for_country(ping['country'])
        
        return pings
    except Exception as e:
        print(f"Error getting pings: {e}")
        return []

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn:
            with conn.cursor() as c:
                c.execute('''
                    CREATE TABLE IF NOT EXISTS players (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        country TEXT NOT NULL,
                        tier TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        social_links TEXT,
                        pin TEXT,
                        is_admin BOOLEAN DEFAULT FALSE
                    )
                ''')
    finally:
        conn.close()

init_db()

# Add missing columns if they don't exist
conn = psycopg2.connect(DATABASE_URL)
try:
    with conn:
        with conn.cursor() as c:
            # Check and add social_links column
            c.execute("""SELECT column_name FROM information_schema.columns 
                         WHERE table_name='players' AND column_name='social_links'""")
            if not c.fetchone():
                c.execute("ALTER TABLE players ADD COLUMN social_links TEXT")
            
            # Check and add pin column
            c.execute("""SELECT column_name FROM information_schema.columns 
                         WHERE table_name='players' AND column_name='pin'""")
            if not c.fetchone():
                c.execute("ALTER TABLE players ADD COLUMN pin TEXT")
            
            # Check and add is_admin column
            c.execute("""SELECT column_name FROM information_schema.columns 
                         WHERE table_name='players' AND column_name='is_admin'""")
            if not c.fetchone():
                c.execute("ALTER TABLE players ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
finally:
    conn.close()
# Add password column migration  
conn2 = psycopg2.connect(DATABASE_URL)
try:
    with conn2:
        with conn2.cursor() as c:
            # Add new password column
            c.execute("""SELECT column_name FROM information_schema.columns 
                         WHERE table_name='players' AND column_name='password'""")
            if not c.fetchone():
                c.execute("ALTER TABLE players ADD COLUMN password TEXT")
                print("Password column added successfully")
except Exception as e:
    print(f"Migration error: {e}")
finally:
    conn2.close()

def sanitize_input(text):
    return re.sub(r'[^\w\s\-\.\$]', '', text)

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        ip = request.remote_addr
        now = time.time()

        honeypot = request.form.get("email_confirm", "")
        if honeypot:
            flash("Spam detected. Submission rejected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        name = sanitize_input(request.form.get("name", ""))
        country = request.form.get("country", "")
        tier = request.form.get("tier", "")
        password = sanitize_input(request.form.get("password", ""))
        social_links = sanitize_input(request.form.get("social_links", ""))

        if not name or not country or not tier or not password:
            flash("Please fill in all required fields.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        if country not in countries or tier not in tiers:
            flash("Invalid country or rank tier selected.", "error")
            return render_template("register.html", countries=countries, tiers=tiers)

        conn = get_db_connection()
        try:
            with conn.cursor() as c:
                c.execute("SELECT COUNT(*) FROM players WHERE name = %s", (name,))
                exists = c.fetchone()[0]

                if exists > 0:
                    flash(f"Username '{name}' is already registered.", "error")
                    return render_template("register.html", countries=countries, tiers=tiers)

                registered_at = datetime.now(timezone.utc).isoformat()
                try:
                    c.execute("INSERT INTO players (name, country, tier, registered_at, social_links, password) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                        (name, country, tier, registered_at, social_links, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))
                    user_id = c.fetchone()[0]
                    conn.commit()
                    session["user_id"] = user_id
                    session["user_name"] = name
                    session["role"] = "user"
                    flash(f"Player '{name}' registered successfully!", "success")
                    return redirect(url_for("players"))
                except Exception as e:
                    flash(f"Database error: {e}", "error")
        finally:
            conn.close()

    return render_template("register.html", countries=countries, tiers=tiers)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        now = time.time()
        
        name = sanitize_input(request.form.get("name", ""))
        password = sanitize_input(request.form.get("password", ""))

        # Check for admin login
        if name == ADMIN_USERNAME and password == ADMIN_PIN:
            # Check if admin user exists in database, create if not
            conn = get_db_connection()
            try:
                with conn.cursor() as c:
                    c.execute("SELECT id FROM players WHERE name = %s AND is_admin = TRUE", (ADMIN_USERNAME,))
                    admin_user = c.fetchone()
                    
                    if not admin_user:
                        # Create admin user in database
                        registered_at = datetime.now(timezone.utc).isoformat()
                        c.execute("""INSERT INTO players (name, country, tier, registered_at, social_links, password, is_admin)
                           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                          (ADMIN_USERNAME, "Global", "God", registered_at, "Admin Account", password, True))
                        admin_id = c.fetchone()[0]
                        conn.commit()
                    else:
                        admin_id = admin_user[0]
                    
                    session["user_id"] = admin_id
                    session["user_name"] = ADMIN_USERNAME
                    session["role"] = "admin"
                    flash("Admin login successful!", "success")
                    return redirect(url_for("players"))
            finally:
                conn.close()

        # Regular user login
        conn = get_db_connection()
        try:
            with conn.cursor() as c:
                c.execute("SELECT id, name, password FROM players WHERE name = %s", (name,))
                
                user = c.fetchone()
                if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                    session["user_id"] = user[0]
                    session["user_name"] = user[1]
                    session["role"] = "user"
                    flash("Login successful!", "success")
                    return redirect(url_for("players"))
                else:
                    flash("Invalid name or password.", "error")
        finally:
            conn.close()

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    response = redirect(url_for("login"))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("SELECT name as username, country, tier, social_links FROM players WHERE id = %s", (user_id,))
            user = c.fetchone()

            if not user:
                flash("User not found.", "error")
                return redirect(url_for("players"))

            if request.method == "POST":
                new_name = sanitize_input(request.form.get("name", ""))
                new_country = request.form.get("country", "")
                new_tier = request.form.get("tier", "")
                new_social_links = sanitize_input(request.form.get("social_links", ""))

                if not new_name or new_country not in countries or new_tier not in tiers:
                    flash("Invalid input.", "error")
                else:
                    # Check if new name is already taken by another user
                    c.execute("SELECT COUNT(*) FROM players WHERE name = %s AND id != %s", (new_name, user_id))
                    name_taken = c.fetchone()[0]
                    
                    if name_taken > 0:
                        flash("Username is already taken.", "error")
                    else:
                        c.execute("UPDATE players SET name = %s, country = %s, tier = %s, social_links = %s WHERE id = %s",
                                  (new_name, new_country, new_tier, new_social_links, user_id))
                        conn.commit()
                        session["user_name"] = new_name  # Update session
                        flash("Profile updated successfully.", "success")
    finally:
        conn.close()

    return render_template("edit_profile.html", user=user, countries=countries, tiers=tiers)

@app.route("/confirm_delete/<int:player_id>")
def confirm_delete(player_id):
    user_role = session.get("role")
    user_id = session.get("user_id")
    if user_role != "admin" and user_id != player_id:
        return "Unauthorized", 403
    return render_template("confirm_delete.html", player_id=player_id)

@app.route("/delete_player/<int:player_id>", methods=["POST"])
def delete_player(player_id):
    user_role = session.get("role")
    user_id = session.get("user_id")
    if user_role != "admin" and user_id != player_id:
        return "Unauthorized", 403

    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as c:
                c.execute("DELETE FROM players WHERE id = %s", (player_id,))
            conn.commit()
            flash("Player deleted successfully.", "success")
            # If user deleted their own profile, clear session
            if user_id == player_id:
                session.clear()
        finally:
            conn.close()
    except Exception as e:
        flash(f"Error deleting player: {e}", "error")

    return redirect(url_for("players"))

@app.route("/admin_delete_profile/<int:player_id>", methods=["POST"])
def admin_delete_profile(player_id):
    if session.get("role") != "admin":
        return "Unauthorized", 403
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as c:
                # Get player name for flash message
                c.execute("SELECT name FROM players WHERE id = %s", (player_id,))
                player = c.fetchone()
                player_name = player[0] if player else "Unknown"
                
                c.execute("DELETE FROM players WHERE id = %s", (player_id,))
            conn.commit()
            flash(f"Player '{player_name}' deleted by admin.", "success")
        finally:
            conn.close()
    except Exception as e:
        flash(f"Admin deletion failed: {e}", "error")
    return redirect(url_for("players"))

@app.route("/players")
def players():
    search_name = request.args.get("name", "").strip()
    search_country = request.args.get("country", "").strip()
    search_tier = request.args.get("tier", "").strip()

    # Fixed: Use alias to match template expectations
    query = "SELECT id, name as username, country, tier, registered_at, social_links, is_admin FROM players WHERE 1=1 AND is_admin = FALSE"
    params = []

    if search_name:
        query += " AND name ILIKE %s"
        params.append(f"%{search_name}%")
    if search_country and search_country in countries:
        query += " AND country = %s"
        params.append(search_country)
    if search_tier and search_tier in tiers:
        query += " AND tier = %s"
        params.append(search_tier)

    query += " ORDER BY registered_at DESC"

    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(query, params)
            players_list = c.fetchall()
    finally:
        conn.close()

    # Fixed: Updated columns to match the aliased query
    columns = ['id', 'username', 'country', 'tier', 'registered_at', 'social_links', 'is_admin']
    players_with_local_time = []
    
    for player_tuple in players_list:
        # Convert tuple to dictionary
        player_dict = dict(zip(columns, player_tuple))
        # Add local time
        local_time = get_local_time_for_country(player_dict['country'])
        player_dict['local_time'] = local_time
        players_with_local_time.append(player_dict)

    # Get ping notifications for current user
    user_pings = []
    if 'user_id' in session:
        user_pings = get_user_pings(session['user_id'])

    return render_template("players.html", 
                           players=players_with_local_time,
                           countries=countries,
                           tiers=tiers,
                           search_name=search_name,
                           search_country=search_country,
                           search_tier=search_tier,
                           user_pings=user_pings,
                           template_version=int(time.time()))

@app.route("/ping/<int:player_id>", methods=["POST"])
def ping_player(player_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    sender_id = session['user_id']
    
    # Don't let users ping themselves
    if sender_id == player_id:
        return jsonify({'error': 'Cannot ping yourself'}), 400

    try:
        import sqlite3
        from datetime import datetime
        
        # Get sender info from users table
        conn = sqlite3.connect('users.db')  # or players.db - whichever has user info
        cursor = conn.cursor()
        cursor.execute("SELECT username, country FROM users WHERE id = ?", (sender_id,))
        sender_info = cursor.fetchone()
        conn.close()
        
        if not sender_info:
            return jsonify({'error': 'Sender not found'}), 400
            
        sender_name, sender_country = sender_info
        
        # Get sender's local time (you might need to adjust this based on your time logic)
        sender_local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Insert into pings table
        conn = sqlite3.connect('players.db')  # assuming pings table is here
        cursor = conn.cursor()
        
        # Insert into pings table
        cursor.execute("""
            INSERT INTO pings (sender_id, receiver_id, timestamp) 
            VALUES (?, ?, ?)
        """, (sender_id, player_id, datetime.now().isoformat()))
        
        # Insert into ping notification table
        cursor.execute("""
            INSERT INTO "ping notification" (sender_name, sender_country, sender_local_time, receiver_id, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (sender_name, sender_country, sender_local_time, player_id, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Ping sent successfully!'}), 200
        
    except Exception as e:
        print(f"Ping error: {e}")  # This will show in your Render logs
        return jsonify({'error': 'Failed to send ping'}), 500
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Insert the ping record
        cur.execute("""
            INSERT INTO pings (sender_id, receiver_id) 
            VALUES (%s, %s)
        """, (sender_id, player_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Ping error: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route("/mark_ping_read/<int:ping_id>", methods=["POST"])
def mark_ping_read(ping_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Mark ping as read only if it belongs to the current user
        cur.execute("""
            UPDATE pings SET is_read = TRUE 
            WHERE id = %s AND receiver_id = %s
        """, (ping_id, user_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Mark ping read error: {e}")
        return jsonify({'error': 'Database error'}), 500

@csrf.exempt
@app.route("/get_time", methods=["POST"])
def get_time():
    data = request.get_json()
    country = data.get("country")
    if not country:
        return jsonify({"time": "Unknown", "timezone": None}), 400
    try:
        time_str = get_local_time_for_country(country, include_timezone=True)
        return jsonify(time_str)
    except Exception as e:
        print(f"Error in /get_time: {e}")
        return jsonify({"time": "Error", "timezone": None}), 500

@lru_cache(maxsize=1000)
def get_local_time_for_country(country_name, include_timezone=False):
    try:
        location = geolocator.geocode(country_name)
        if not location:
            return {"time": "N/A", "timezone": None} if include_timezone else "N/A"
        tz_name = tz_finder.timezone_at(lat=location.latitude, lng=location.longitude)
        if not tz_name:
            return {"time": "N/A", "timezone": None} if include_timezone else "N/A"
        tz = pytz.timezone(tz_name)
        now = datetime.now(tz)
        if include_timezone:
            return {"time": now.strftime("%H:%M:%S"), "timezone": tz_name}
        return now.strftime("%H:%M")
    except:
        return {"time": "N/A", "timezone": None} if include_timezone else "N/A"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)