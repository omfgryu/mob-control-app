# app.py - Complete version with Game Rank System (WebSockets REMOVED)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import session, Flask, render_template, request, jsonify, redirect, url_for, flash, g, send_from_directory, make_response
from datetime import datetime, timezone, timedelta
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
from functools import lru_cache
import atexit
import time

app = Flask(__name__)
csrf = CSRFProtect(app)

# ✅ SIMPLIFIED SETTINGS - NO WEBSOCKET COMPLEXITY
MAX_PINGS_PER_MINUTE = 8  # Rate limiting for HTTP pings
PING_RATE_STORE = {}  # Simple in-memory rate limiting

# ✅ FRONTEND CACHING
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with optimized caching headers"""
    try:
        response = make_response(send_from_directory('static', filename))
        file_ext = filename.split('.')[-1].lower()
        
        if file_ext in ['css', 'js']:
            response.headers['Cache-Control'] = 'public, max-age=2592000'  # 30 days
            response.headers['ETag'] = f'"{hash(filename)}"'
        elif file_ext in ['mp3', 'wav', 'ogg', 'mp4']:
            response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 year
        elif file_ext in ['png', 'jpg', 'jpeg', 'gif', 'ico', 'svg']:
            response.headers['Cache-Control'] = 'public, max-age=604800'  # 1 week
        else:
            response.headers['Cache-Control'] = 'public, max-age=3600'  # 1 hour
        
        response.headers['Vary'] = 'Accept-Encoding'
        return response
    except Exception as e:
        print(f"Static file error: {e}")
        return "File not found", 404

@app.after_request
def after_request(response):
    if request.endpoint != 'static_files':
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

app.config['DEBUG'] = True
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    app.config['SECRET_KEY'] = 'mysecretkey123456789'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 604800  # 1 week

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'omfgryu')
ADMIN_PIN = os.environ.get('ADMIN_PIN', 'gogetassj4')

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
    DATABASE_URL = 'postgresql://neondb_owner:npg_JluO3d8qXLBa@ep-frosty-river-a1uyt8sc-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require'

# ✅ SIMPLIFIED CONNECTION POOL
try:
    connection_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=8,  # Reduced from 10
        dsn=DATABASE_URL,
    )
    print("✅ Lightweight connection pool created successfully!")
except Exception as e:
    print(f"❌ Error creating connection pool: {e}")
    connection_pool = None

def get_db_connection():
    """Database connection with proper pool management"""
    if connection_pool:
        try:
            conn = connection_pool.getconn()
            if conn:
                return conn
        except Exception as e:
            print(f"Pool connection error: {e}")
    
    print("Using fallback connection...")
    return psycopg2.connect(DATABASE_URL)

def release_db_connection(conn):
    """Return connection to pool or close it"""
    if connection_pool and conn:
        try:
            connection_pool.putconn(conn)
        except Exception as e:
            print(f"Error returning connection to pool: {e}")
            try:
                conn.close()
            except:
                pass
    else:
        try:
            conn.close()
        except:
            pass

def cleanup_connection_pool():
    """Close all connections in pool on shutdown"""
    global connection_pool
    if connection_pool:
        try:
            connection_pool.closeall()
            print("✅ Connection pool closed successfully")
        except Exception as e:
            print(f"Error closing connection pool: {e}")

atexit.register(cleanup_connection_pool)

geolocator = Nominatim(user_agent="mob_control_app", timeout=5)
tz_finder = TimezoneFinder()

def cache_bust_static(filename):
    """Add cache busting parameter to static files"""
    try:
        file_path = os.path.join('static', filename)
        if os.path.exists(file_path):
            mtime = str(int(os.path.getmtime(file_path)))
            return f"{filename}?v={mtime}"
        return filename
    except:
        return filename

@app.context_processor
def utility_processor():
    return dict(cache_bust=cache_bust_static)

# ✅ SIMPLE RATE LIMITING
def check_ping_rate_limit(user_id):
    """Simple rate limiting without complex tracking"""
    current_time = time.time()
    
    if user_id not in PING_RATE_STORE:
        PING_RATE_STORE[user_id] = []
    
    # Clean old entries
    PING_RATE_STORE[user_id] = [
        timestamp for timestamp in PING_RATE_STORE[user_id]
        if current_time - timestamp < 60
    ]
    
    if len(PING_RATE_STORE[user_id]) >= MAX_PINGS_PER_MINUTE:
        return False
    
    PING_RATE_STORE[user_id].append(current_time)
    return True

# ✅ DATABASE FUNCTIONS
def get_user_pings(user_id):
    """Get grouped ping notifications for a user"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT 
                p.sender_id,
                u.name as username,
                u.country,
                COUNT(*) as ping_count,
                MAX(p.timestamp) as latest_timestamp,
                MIN(p.id) as first_ping_id
            FROM pings p
            JOIN players u ON p.sender_id = u.id
            WHERE p.receiver_id = %s AND p.is_read = FALSE
            GROUP BY p.sender_id, u.name, u.country
            ORDER BY latest_timestamp DESC
        """, (user_id,))
        
        ping_groups = cur.fetchall()
        cur.close()
        return ping_groups
        
    except Exception as e:
        print(f"Error getting pings: {e}")
        return []
    finally:
        if conn:
            release_db_connection(conn)

def init_db():
    conn = None
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor() as c:
                # Create players table
                c.execute('''
                    CREATE TABLE IF NOT exists players (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        country TEXT NOT NULL,
                        tier TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        social_links TEXT,
                        pin TEXT,
                        is_admin BOOLEAN DEFAULT FALSE,
                        password TEXT,
                        game_rank INTEGER DEFAULT 999999
                    )
                ''')
                
                # Create pings table
                c.execute('''
                    CREATE TABLE IF NOT EXISTS pings (
                        id SERIAL PRIMARY KEY,
                        sender_id INTEGER NOT NULL,
                        receiver_id INTEGER NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_read BOOLEAN DEFAULT FALSE,
                        FOREIGN KEY (sender_id) REFERENCES players (id),
                        FOREIGN KEY (receiver_id) REFERENCES players (id)
                    )
                ''')
                
                # Performance indexes
                indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_players_name ON players(name)",
                    "CREATE INDEX IF NOT EXISTS idx_players_country ON players(country)",
                    "CREATE INDEX IF NOT EXISTS idx_players_tier ON players(tier)",
                    "CREATE INDEX IF NOT EXISTS idx_players_registered ON players(registered_at)",
                    "CREATE INDEX IF NOT EXISTS idx_players_game_rank ON players(game_rank)",
                    "CREATE INDEX IF NOT EXISTS idx_pings_receiver_unread ON pings(receiver_id, is_read)",
                    "CREATE INDEX IF NOT EXISTS idx_pings_timestamp ON pings(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_pings_sender ON pings(sender_id)"
                ]
                
                for index in indexes:
                    c.execute(index)
                
                print("✅ Database tables and indexes created successfully!")
                
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        if conn:
            release_db_connection(conn)

init_db()

# ✅ ADD MISSING COLUMNS (INCLUDING GAME_RANK)
conn = None
try:
    conn = get_db_connection()
    with conn:
        with conn.cursor() as c:
            columns_to_add = [
                ("social_links", "ALTER TABLE players ADD COLUMN social_links TEXT"),
                ("pin", "ALTER TABLE players ADD COLUMN pin TEXT"),
                ("is_admin", "ALTER TABLE players ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"),
                ("password", "ALTER TABLE players ADD COLUMN password TEXT"),
                ("game_rank", "ALTER TABLE players ADD COLUMN game_rank INTEGER DEFAULT 999999")
            ]
            
            for column_name, alter_query in columns_to_add:
                c.execute(f"""SELECT column_name FROM information_schema.columns 
                             WHERE table_name='players' AND column_name='{column_name}'""")
                if not c.fetchone():
                    c.execute(alter_query)
                    print(f"✅ {column_name} column added successfully")
                    
except Exception as e:
    print(f"Column migration error: {e}")
finally:
    if conn:
        release_db_connection(conn)

def sanitize_input(text):
    return re.sub(r'[^\w\s\-\.\$]', '', text)

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

# ✅ ROUTES
@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
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

        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as c:
                c.execute("SELECT COUNT(*) FROM players WHERE name = %s", (name,))
                exists = c.fetchone()[0]

                if exists > 0:
                    flash(f"Username '{name}' is already registered.", "error")
                    return render_template("register.html", countries=countries, tiers=tiers)

                registered_at = datetime.now(timezone.utc).isoformat()
                c.execute("INSERT INTO players (name, country, tier, registered_at, social_links, password, game_rank) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (name, country, tier, registered_at, social_links, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 999999))
                user_id = c.fetchone()[0]
                conn.commit()
                
                session["user_id"] = user_id
                session["user_name"] = name
                session["role"] = "user"
                
                flash(f"Player '{name}' registered successfully!", "success")
                return redirect(url_for("players"))
                
        except Exception as e:
            flash(f"Registration error: {e}", "error")
        finally:
            if conn:
                release_db_connection(conn)

    return render_template("register.html", countries=countries, tiers=tiers)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""))
        password = sanitize_input(request.form.get("password", ""))
        remember_me = request.form.get("remember_me")

        # Check for admin login
        if name == ADMIN_USERNAME and password == ADMIN_PIN:
            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor() as c:
                    c.execute("SELECT id FROM players WHERE name = %s AND is_admin = TRUE", (ADMIN_USERNAME,))
                    admin_user = c.fetchone()
                    
                    if not admin_user:
                        registered_at = datetime.now(timezone.utc).isoformat()
                        c.execute("""INSERT INTO players (name, country, tier, registered_at, social_links, password, is_admin, game_rank)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                          (ADMIN_USERNAME, "Global", "God", registered_at, "Admin Account", password, True, 1))
                        admin_id = c.fetchone()[0]
                        conn.commit()
                    else:
                        admin_id = admin_user[0]
                    
                    if remember_me:
                        session.permanent = True
                    
                    session["user_id"] = admin_id
                    session["user_name"] = ADMIN_USERNAME
                    session["role"] = "admin"
                    
                    flash("Admin login successful!", "success")
                    return redirect(url_for("players"))
            except Exception as e:
                flash(f"Admin login error: {e}", "error")
            finally:
                if conn:
                    release_db_connection(conn)

        # Regular user login
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as c:
                c.execute("SELECT id, name, password FROM players WHERE name = %s", (name,))
                
                user = c.fetchone()
                if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                    if remember_me:
                        session.permanent = True
                    
                    session["user_id"] = user[0]
                    session["user_name"] = user[1]
                    session["role"] = "user"
                    flash("Login successful!", "success")
                    return redirect(url_for("players"))
                else:
                    flash("Invalid name or password.", "error")
        except Exception as e:
            flash(f"Login error: {e}", "error")
        finally:
            if conn:
                release_db_connection(conn)

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

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("SELECT name as username, country, tier, social_links, game_rank FROM players WHERE id = %s", (user_id,))
            user_tuple = c.fetchone()
            print(f"DEBUG: User data: {user_tuple}")
            if user_tuple:
                user = {
                    'username': user_tuple[0],
                    'country': user_tuple[1], 
                    'tier': user_tuple[2],
                    'social_links': user_tuple[3],
                    'game_rank': user_tuple[4]
                }
            else:
                user = None

            if not user:
                flash("User not found.", "error")
                return redirect(url_for("players"))

            if request.method == "POST":
                new_name = sanitize_input(request.form.get("name", ""))
                new_country = request.form.get("country", "")
                new_tier = request.form.get("tier", "")
                new_social_links = sanitize_input(request.form.get("social_links", ""))
                new_game_rank = request.form.get("game_rank", "999999")
                
                # Validate game rank
                try:
                    game_rank_int = int(new_game_rank)
                    if game_rank_int < 1 or game_rank_int > 999999:
                        game_rank_int = 999999
                except (ValueError, TypeError):
                    game_rank_int = 999999

                if not new_name or new_country not in countries or new_tier not in tiers:
                    flash("Invalid input.", "error")
                else:
                    c.execute("SELECT COUNT(*) FROM players WHERE name = %s AND id != %s", (new_name, user_id))
                    name_taken = c.fetchone()[0]
                    
                    if name_taken > 0:
                        flash("Username is already taken.", "error")
                    else:
                        c.execute("UPDATE players SET name = %s, country = %s, tier = %s, social_links = %s, game_rank = %s WHERE id = %s",
                                  (new_name, new_country, new_tier, new_social_links, game_rank_int, user_id))
                        conn.commit()
                        session["user_name"] = new_name
                        flash("Profile updated successfully.", "success")
                        return redirect(url_for("players"))
    except Exception as e:
        flash(f"Profile update error: {e}", "error")
    finally:
        if conn:
            release_db_connection(conn)

    return render_template("edit_profile.html", user=user, countries=countries, tiers=tiers)

@app.route("/update_rank", methods=["POST"])
def update_rank():
    """Update player's game rank"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_id = session['user_id']
    data = request.get_json()
    
    try:
        new_rank = int(data.get('rank', 999999))
        if new_rank < 1 or new_rank > 999999:
            return jsonify({'error': 'Rank must be between 1 and 999,999'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid rank value'}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("UPDATE players SET game_rank = %s WHERE id = %s", (new_rank, user_id))
        conn.commit()
        cur.close()
        
        return jsonify({'success': True, 'rank': new_rank}), 200
        
    except Exception as e:
        print(f"Update rank error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if conn:
            release_db_connection(conn)

@app.route("/delete_player/<int:player_id>", methods=["POST"])
def delete_player(player_id):
    user_role = session.get("role")
    user_id = session.get("user_id")
    if user_role != "admin" and user_id != player_id:
        return "Unauthorized", 403

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("DELETE FROM players WHERE id = %s", (player_id,))
        conn.commit()
        flash("Player deleted successfully.", "success")
        if user_id == player_id:
            session.clear()
    except Exception as e:
        flash(f"Error deleting player: {e}", "error")
    finally:
        if conn:
            release_db_connection(conn)

    return redirect(url_for("players"))

@app.route("/admin_delete_profile/<int:player_id>", methods=["POST"])
def admin_delete_profile(player_id):
    if session.get("role") != "admin":
        return "Unauthorized", 403
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("SELECT name FROM players WHERE id = %s", (player_id,))
            player = c.fetchone()
            player_name = player[0] if player else "Unknown"
            
            c.execute("DELETE FROM players WHERE id = %s", (player_id,))
        conn.commit()
        flash(f"Player '{player_name}' deleted by admin.", "success")
    except Exception as e:
        flash(f"Admin deletion failed: {e}", "error")
    finally:
        if conn:
            release_db_connection(conn)
    
    return redirect(url_for("players"))

@app.route("/players")
def players():
    search_name = request.args.get("name", "").strip()
    search_country = request.args.get("country", "").strip()
    search_tier = request.args.get("tier", "").strip()

    # ✅ UPDATED QUERY WITH GAME_RANK
    query = "SELECT id, name as username, country, tier, registered_at, social_links, is_admin, game_rank FROM players WHERE 1=1 AND is_admin = FALSE"
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

    # ✅ SORT BY GAME RANK (ascending - rank 1 first)
    query += " ORDER BY game_rank ASC, registered_at DESC"

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute(query, params)
            players_list = c.fetchall()
    except Exception as e:
        print(f"Players query error: {e}")
        players_list = []
    finally:
        if conn:
            release_db_connection(conn)

    # ✅ UPDATED COLUMNS LIST
    columns = ['id', 'username', 'country', 'tier', 'registered_at', 'social_links', 'is_admin', 'game_rank']
    players_with_local_time = []
    
    for player_tuple in players_list:
        player_dict = dict(zip(columns, player_tuple))
        local_time = get_local_time_for_country(player_dict['country'])
        player_dict['local_time'] = local_time
        players_with_local_time.append(player_dict)

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

@app.route("/notifications")
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_pings = get_user_pings(session['user_id'])
    return render_template("notifications.html", user_pings=user_pings)

@app.route("/ping/<int:player_id>", methods=["POST"])
def ping_player(player_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    sender_id = session['user_id']
    
    if sender_id == player_id:
        return jsonify({'error': 'Cannot ping yourself'}), 400

    # Check rate limiting
    if not check_ping_rate_limit(sender_id):
        return jsonify({'error': f'Rate limit exceeded. Max {MAX_PINGS_PER_MINUTE} pings per minute.'}), 429

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO pings (sender_id, receiver_id, timestamp, is_read) 
            SELECT %s, %s, CURRENT_TIMESTAMP, FALSE
            WHERE EXISTS (SELECT 1 FROM players WHERE id = %s)
            RETURNING id
        """, (sender_id, player_id, sender_id))
        
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({'error': 'Sender not found'}), 400
        
        conn.commit()
        cur.close()
        
        return jsonify({'success': True, 'message': 'Ping sent successfully!'}), 200
        
    except Exception as e:
        print(f"Ping error: {e}")
        return jsonify({'error': 'Failed to send ping'}), 500
    finally:
        if conn:
            release_db_connection(conn)

@app.route("/mark_ping_read/<int:sender_id>", methods=["POST"])
def mark_ping_read(sender_id):
    """Mark all pings from a specific sender as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_id = session['user_id']
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            UPDATE pings SET is_read = TRUE 
            WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
        """, (sender_id, user_id))
        
        conn.commit()
        cur.close()
        
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Mark ping read error: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        if conn:
            release_db_connection(conn)

@app.route("/get_time", methods=["POST"])
@csrf.exempt
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print("🚀 Lightweight server starting - No WebSockets!")
    print("💾 Simple HTTP-based ping system active")
    print("🏆 Game Rank system enabled")
    print("📊 CPU usage should be MUCH lower!")
    app.run(host="0.0.0.0", port=port, debug=True)