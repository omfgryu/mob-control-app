# app.py
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import session, Flask, render_template, request, jsonify, redirect, url_for, flash, g, send_from_directory, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
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
from collections import defaultdict
import time
from functools import lru_cache
import atexit
import hashlib

app = Flask(__name__)
csrf = CSRFProtect(app)

# ✅ REAL-TIME WEBSOCKET SETUP
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active users for real-time features
active_users = {}  # {user_id: {'username': 'name', 'sid': 'socket_id', 'last_seen': timestamp}}

# ✅ FRONTEND CACHING - Cache static files for 1 year, but allow updates
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with optimized caching headers"""
    try:
        # Create response for static file
        response = make_response(send_from_directory('static', filename))
        
        # Get file extension for different cache strategies
        file_ext = filename.split('.')[-1].lower()
        
        if file_ext in ['css', 'js']:
            # CSS/JS files - Cache for 30 days but allow updates
            response.headers['Cache-Control'] = 'public, max-age=2592000'  # 30 days
            response.headers['ETag'] = f'"{hash(filename)}"'
            
        elif file_ext in ['mp3', 'wav', 'ogg', 'mp4']:
            # Audio/Video files - Cache for 1 year (rarely change)
            response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 year
            
        elif file_ext in ['png', 'jpg', 'jpeg', 'gif', 'ico', 'svg']:
            # Images - Cache for 1 week
            response.headers['Cache-Control'] = 'public, max-age=604800'  # 1 week
            
        else:
            # Other files - Cache for 1 hour
            response.headers['Cache-Control'] = 'public, max-age=3600'  # 1 hour
        
        # Add compression hint
        response.headers['Vary'] = 'Accept-Encoding'
        
        return response
        
    except Exception as e:
        print(f"Static file error: {e}")
        return "File not found", 404

# Add after_request decorator to the app
@app.after_request
def after_request(response):
    # Only apply no-cache headers to HTML pages, not static files
    if request.endpoint != 'static_files':
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    
    # Add performance headers for all responses
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    return response

app.config['DEBUG'] = True
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable is required")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 604800  # 1 week for Remember Me

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

# ✅ OPTIMIZED CONNECTION POOL - Better configuration for free tier
try:
    # Optimized pool settings for better performance on free tier:
    # - min_conn=2: Always keep 2 connections ready (faster response)
    # - max_conn=10: Reduced from 20 to stay within free tier limits
    # - Better resource management
    connection_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=2,           # Keep minimum 2 connections ready
        maxconn=10,          # Max 10 connections (free tier friendly)
        dsn=DATABASE_URL,
        # Connection optimization parameters
        options='-c statement_timeout=30000'  # 30 second timeout
    )
    print("✅ Optimized connection pool created successfully!")
except Exception as e:
    print(f"❌ Error creating connection pool: {e}")
    connection_pool = None

# ✅ OPTIMIZED CONNECTION MANAGEMENT
def get_db_connection():
    """Optimized database connection with proper pool management"""
    if connection_pool:
        try:
            # Get connection from pool (much faster than creating new connection)
            conn = connection_pool.getconn()
            if conn:
                return conn
        except Exception as e:
            print(f"Pool connection error: {e}")
    
    # Fallback to direct connection if pool fails
    print("Using fallback connection...")
    return psycopg2.connect(DATABASE_URL)

def release_db_connection(conn):
    """Properly return connection to pool or close it"""
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

# ✅ GRACEFUL SHUTDOWN - Properly close pool on app shutdown
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

# ✅ TEMPLATE CACHE BUSTING - Add version numbers to static files
def cache_bust_static(filename):
    """Add cache busting parameter to static files"""
    try:
        # Use file modification time as version
        file_path = os.path.join('static', filename)
        if os.path.exists(file_path):
            mtime = str(int(os.path.getmtime(file_path)))
            return f"{filename}?v={mtime}"
        return filename
    except:
        return filename

# Make cache_bust_static available in templates
@app.context_processor
def utility_processor():
    return dict(cache_bust=cache_bust_static)

# ✅ REAL-TIME WEBSOCKET EVENT HANDLERS

@socketio.on('connect')
def handle_connect():
    """Handle user connecting to WebSocket"""
    user_id = session.get('user_id')
    username = session.get('user_name')
    
    if user_id and username:
        # Add user to active users
        active_users[user_id] = {
            'username': username,
            'sid': request.sid,
            'last_seen': time.time()
        }
        
        # Join user to their personal room for notifications
        join_room(f"user_{user_id}")
        
        # Broadcast user came online to all users
        socketio.emit('user_status_update', {
            'user_id': user_id,
            'username': username,
            'status': 'online'
        }, broadcast=True)
        
        print(f"✅ {username} connected - Active users: {len(active_users)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnecting from WebSocket"""
    user_id = session.get('user_id')
    username = session.get('user_name')
    
    if user_id in active_users:
        # Remove user from active users
        del active_users[user_id]
        
        # Leave user's personal room
        leave_room(f"user_{user_id}")
        
        # Broadcast user went offline to all users
        socketio.emit('user_status_update', {
            'user_id': user_id,
            'username': username,
            'status': 'offline'
        }, broadcast=True)
        
        print(f"❌ {username} disconnected - Active users: {len(active_users)}")

@socketio.on('ping_user')
def handle_ping_user(data):
    """Handle real-time ping sending"""
    sender_id = session.get('user_id')
    sender_name = session.get('user_name')
    receiver_id = data.get('receiver_id')
    
    if not sender_id or not receiver_id:
        emit('ping_error', {'error': 'Invalid user data'})
        return
    
    if sender_id == receiver_id:
        emit('ping_error', {'error': 'Cannot ping yourself'})
        return
    
    # Save ping to database
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO pings (sender_id, receiver_id, timestamp, is_read) 
            SELECT %s, %s, CURRENT_TIMESTAMP, FALSE
            WHERE EXISTS (SELECT 1 FROM players WHERE id = %s)
            RETURNING id
        """, (sender_id, receiver_id, sender_id))
        
        result = cur.fetchone()
        if result:
            conn.commit()
            ping_id = result[0]
            
            # Send real-time notification to receiver
            socketio.emit('new_ping_notification', {
                'ping_id': ping_id,
                'sender_id': sender_id,
                'sender_name': sender_name,
                'timestamp': datetime.now().isoformat(),
                'message': f'{sender_name} pinged you!'
            }, room=f"user_{receiver_id}")
            
            # Confirm to sender
            emit('ping_success', {'message': f'Pinged {data.get("receiver_name", "user")}!'})
            
            print(f"📡 Real-time ping: {sender_name} → {receiver_id}")
        else:
            emit('ping_error', {'error': 'Failed to send ping'})
        
        cur.close()
        
    except Exception as e:
        print(f"Ping error: {e}")
        emit('ping_error', {'error': 'Database error'})
    finally:
        if conn:
            release_db_connection(conn)

@socketio.on('get_active_users')
def handle_get_active_users():
    """Send list of currently active users"""
    active_list = []
    for user_id, user_data in active_users.items():
        active_list.append({
            'user_id': user_id,
            'username': user_data['username'],
            'last_seen': user_data['last_seen']
        })
    
    emit('active_users_list', {'active_users': active_list})

def cleanup_old_pings():
    """Auto-cleanup: Delete pings older than 24 hours and limit to 10 per user"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Delete pings older than 24 hours
        cur.execute("""
            DELETE FROM pings 
            WHERE timestamp < %s
        """, (datetime.now() - timedelta(hours=24),))
        
        # For each receiver, keep only the 10 most recent pings
        cur.execute("""
            DELETE FROM pings 
            WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY receiver_id ORDER BY timestamp DESC) as rn
                    FROM pings
                ) ranked 
                WHERE rn <= 10
            )
        """)
        
        conn.commit()
        cur.close()
        print("Ping cleanup completed")
        
    except Exception as e:
        print(f"Error during ping cleanup: {e}")
    finally:
        if conn:
            release_db_connection(conn)

def get_user_pings(user_id):
    """Get grouped ping notifications for a user"""
    conn = None
    try:
        # Auto-cleanup old pings first
        cleanup_old_pings()
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get grouped pings - count by sender and get latest info
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
                # Create tables
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
                
                # PERFORMANCE INDEXES - Speed up queries by 3-15x
                print("Creating performance indexes...")
                
                # Speed up username searches and filtering
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_players_name 
                    ON players(name)
                ''')
                
                # Speed up country filtering
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_players_country 
                    ON players(country)
                ''')
                
                # Speed up tier filtering  
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_players_tier 
                    ON players(tier)
                ''')
                
                # Speed up table sorting by registration date
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_players_registered 
                    ON players(registered_at)
                ''')
                
                # Speed up ping notifications (most important for ping system)
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_pings_receiver_unread 
                    ON pings(receiver_id, is_read)
                ''')
                
                # Speed up ping cleanup and timestamp queries
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_pings_timestamp 
                    ON pings(timestamp)
                ''')
                
                # Speed up ping sender queries
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_pings_sender 
                    ON pings(sender_id)
                ''')
                
                print("Performance indexes created successfully!")
                
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        if conn:
            release_db_connection(conn)

init_db()

# Add missing columns if they don't exist
conn = None
try:
    conn = get_db_connection()
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
except Exception as e:
    print(f"Column migration error: {e}")
finally:
    if conn:
        release_db_connection(conn)

# Add password column migration  
conn = None
try:
    conn = get_db_connection()
    with conn:
        with conn.cursor() as c:
            # Add new password column
            c.execute("""SELECT column_name FROM information_schema.columns 
                         WHERE table_name='players' AND column_name='password'""")
            if not c.fetchone():
                c.execute("ALTER TABLE players ADD COLUMN password TEXT")
                print("Password column added successfully")
except Exception as e:
    print(f"Migration error: {e}")
finally:
    if conn:
        release_db_connection(conn)

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
        except Exception as e:
            flash(f"Registration error: {e}", "error")
        finally:
            if conn:
                release_db_connection(conn)

    return render_template("register.html", countries=countries, tiers=tiers)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        now = time.time()
        
        name = sanitize_input(request.form.get("name", ""))
        password = sanitize_input(request.form.get("password", ""))
        remember_me = request.form.get("remember_me")  # Get Remember Me checkbox

        # Check for admin login
        if name == ADMIN_USERNAME and password == ADMIN_PIN:
            # Check if admin user exists in database, create if not
            conn = None
            try:
                conn = get_db_connection()
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
                    
                    # Set permanent session if Remember Me is checked
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
                    # Set permanent session if Remember Me is checked
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
    except Exception as e:
        flash(f"Profile update error: {e}", "error")
    finally:
        if conn:
            release_db_connection(conn)

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

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("DELETE FROM players WHERE id = %s", (player_id,))
        conn.commit()
        flash("Player deleted successfully.", "success")
        # If user deleted their own profile, clear session
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
            # Get player name for flash message
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

    # Get grouped ping notifications for current user
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

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Optimized: Single query that validates sender exists and inserts ping
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
        
        # ✅ REAL-TIME NOTIFICATION - Send instant notification via WebSocket
        sender_name = session.get('user_name', 'Unknown')
        socketio.emit('new_ping_notification', {
            'ping_id': result[0],
            'sender_id': sender_id,
            'sender_name': sender_name,
            'timestamp': datetime.now().isoformat(),
            'message': f'{sender_name} pinged you!'
        }, room=f"user_{player_id}")
        
        return jsonify({'success': True, 'message': 'Ping sent successfully!'}), 200
        
    except Exception as e:
        print(f"Ping error: {e}")  # This will show in your Render logs
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
        
        # Mark all pings from this sender to current user as read
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
    # ✅ Run with SocketIO support
    socketio.run(app, host="0.0.0.0", port=port, debug=True)