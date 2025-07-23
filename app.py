# app.py - Complete version with Smart Load Management and Health Monitoring
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
import threading
import psutil
import gc
from functools import wraps
import pickle

app = Flask(__name__)
csrf = CSRFProtect(app)

# ✅ REAL-TIME WEBSOCKET SETUP
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ✅ SMART LOAD MANAGEMENT SETTINGS
MAX_WEBSOCKET_USERS = 80  # Reserve 20 slots for new users
MAX_TOTAL_CAPACITY = 100  # Total server capacity
PRIORITY_RESERVE = 20     # Reserved slots for new registrations
MAX_PINGS_PER_MINUTE = 8  # Reduced to save resources
MEMORY_CLEANUP_INTERVAL = 300  # 5 minutes
CONNECTION_TIMEOUT = 60  # 1 minute idle timeout

# ✅ HEALTH MONITORING SETTINGS
HEALTH_CHECK_INTERVAL = 60
MEMORY_WARNING_MB = 400
CPU_WARNING_PERCENT = 70
DB_WARNING_CONNECTIONS = 7

health_status = {
    'last_check': 0,
    'memory_mb': 0,
    'cpu_percent': 0,
    'active_users': 0,
    'status': 'healthy',
    'warnings': []
}

# Store active users and management data
active_users = {}  # {user_id: {'username': 'name', 'sid': 'socket_id', 'last_seen': timestamp}}
user_ping_rates = defaultdict(list)  # {user_id: [timestamp1, timestamp2, ...]}
user_activity_scores = {}  # {user_id: activity_score}
last_cleanup = time.time()
last_activity_cleanup = time.time()

# ✅ FRONTEND CACHING - Cache static files for 1 year, but allow updates
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
    raise ValueError("SECRET_KEY environment variable is required")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 604800  # 1 week for Remember Me

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
    raise ValueError("DATABASE_URL environment variable is required")

# ✅ OPTIMIZED CONNECTION POOL
try:
    connection_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=10,
        dsn=DATABASE_URL,
        options='-c statement_timeout=30000'
    )
    print("✅ Optimized connection pool created successfully!")
except Exception as e:
    print(f"❌ Error creating connection pool: {e}")
    connection_pool = None

def get_db_connection():
    """Optimized database connection with proper pool management"""
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

# ✅ SMART LOAD MANAGEMENT FUNCTIONS

def calculate_user_activity_score(user_id):
    """Calculate user activity score for prioritization"""
    if user_id not in active_users:
        return 0
    
    user_data = active_users[user_id]
    current_time = time.time()
    
    connection_time = current_time - user_data.get('connect_time', current_time)
    last_seen = current_time - user_data.get('last_seen', current_time)
    ping_activity = len(user_ping_rates.get(user_id, []))
    
    score = 0
    
    # Recent activity (0-100 points)
    if last_seen < 60:
        score += 100
    elif last_seen < 300:
        score += 50
    elif last_seen < 900:
        score += 20
    
    # Ping activity (0-50 points)
    score += min(ping_activity * 10, 50)
    
    # Connection duration bonus (0-30 points)
    if connection_time > 300:
        score += 30
    elif connection_time > 60:
        score += 15
    
    return score

def smart_connection_management():
    """Smart connection management - prioritize active users"""
    current_capacity = len(active_users)
    
    if current_capacity < MAX_WEBSOCKET_USERS:
        return 'allow'
    
    if current_capacity >= MAX_TOTAL_CAPACITY:
        return 'need_cleanup'
    
    return 'degraded'

def cleanup_inactive_users():
    """Remove least active users to make room"""
    if len(active_users) <= MAX_WEBSOCKET_USERS:
        return
    
    current_time = time.time()
    
    # Calculate activity scores for all users
    user_scores = {}
    for user_id in active_users:
        user_scores[user_id] = calculate_user_activity_score(user_id)
    
    # Sort by activity score (lowest first)
    sorted_users = sorted(user_scores.items(), key=lambda x: x[1])
    
    # Remove least active users until we're under the limit
    users_to_remove = len(active_users) - MAX_WEBSOCKET_USERS
    
    for i in range(min(users_to_remove, len(sorted_users))):
        user_id_to_remove = sorted_users[i][0]
        
        # Don't remove very recently connected users
        if current_time - active_users[user_id_to_remove].get('connect_time', 0) < 120:
            continue
        
        username = active_users[user_id_to_remove]['username']
        
        # Send graceful disconnect message
        socketio.emit('graceful_disconnect', {
            'message': 'Server optimization in progress. Please reconnect in a moment!',
            'reconnect_delay': 30
        }, room=f"user_{user_id_to_remove}")
        
        del active_users[user_id_to_remove]
        print(f"🔄 Gracefully disconnected inactive user: {username} (score: {sorted_users[i][1]})")
        
        if len(active_users) <= MAX_WEBSOCKET_USERS:
            break

def cleanup_memory():
    """Clean up inactive users and old data"""
    global active_users, last_cleanup
    current_time = time.time()
    
    if current_time - last_cleanup < MEMORY_CLEANUP_INTERVAL:
        return
    
    print("🧹 Running memory cleanup...")
    
    # Remove users inactive for more than 5 minutes
    inactive_users = []
    for user_id, user_data in active_users.items():
        if current_time - user_data.get('last_seen', 0) > 300:
            inactive_users.append(user_id)
    
    for user_id in inactive_users:
        del active_users[user_id]
        print(f"🗑️ Removed inactive user: {user_id}")
    
    # Clean old ping rate data
    for user_id in list(user_ping_rates.keys()):
        user_ping_rates[user_id] = [
            timestamp for timestamp in user_ping_rates[user_id]
            if current_time - timestamp < 60
        ]
        if not user_ping_rates[user_id]:
            del user_ping_rates[user_id]
    
    last_cleanup = current_time
    print(f"✅ Memory cleanup complete. Active users: {len(active_users)}")

def check_ping_rate_limit(user_id):
    """Check if user is sending pings too fast"""
    current_time = time.time()
    
    user_ping_rates[user_id] = [
        timestamp for timestamp in user_ping_rates[user_id]
        if current_time - timestamp < 60
    ]
    
    if len(user_ping_rates[user_id]) >= MAX_PINGS_PER_MINUTE:
        return False
    
    user_ping_rates[user_id].append(current_time)
    return True

# ✅ HEALTH MONITORING FUNCTIONS

def check_system_health():
    """Simple health check - run every minute"""
    global health_status
    current_time = time.time()
    
    if current_time - health_status['last_check'] < HEALTH_CHECK_INTERVAL:
        return health_status
    
    try:
        memory_info = psutil.virtual_memory()
        memory_mb = memory_info.used / (1024 * 1024)
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        health_status.update({
            'last_check': current_time,
            'memory_mb': round(memory_mb, 1),
            'cpu_percent': round(cpu_percent, 1),
            'active_users': len(active_users),
            'warnings': []
        })
        
        if memory_mb > MEMORY_WARNING_MB:
            health_status['warnings'].append(f'High memory: {memory_mb:.1f}MB')
            print(f"⚠️ MEMORY WARNING: {memory_mb:.1f}MB")
            
        if cpu_percent > CPU_WARNING_PERCENT:
            health_status['warnings'].append(f'High CPU: {cpu_percent:.1f}%')
            print(f"⚠️ CPU WARNING: {cpu_percent:.1f}%")
            
        if len(active_users) > 85:
            health_status['warnings'].append(f'High user load: {len(active_users)} users')
            print(f"⚠️ USER LOAD WARNING: {len(active_users)} users")
        
        if health_status['warnings']:
            health_status['status'] = 'warning'
            if memory_mb > MEMORY_WARNING_MB or len(active_users) > 90:
                print("🚨 EMERGENCY CLEANUP TRIGGERED")
                emergency_cleanup()
        else:
            health_status['status'] = 'healthy'
            
    except Exception as e:
        print(f"Health check error: {e}")
        health_status['status'] = 'error'
    
    return health_status

def emergency_cleanup():
    """Emergency cleanup when resources are low"""
    try:
        print("🧹 Running emergency cleanup...")
        gc.collect()
        cleanup_memory()
        print(f"✅ Emergency cleanup complete. Users: {len(active_users)}")
    except Exception as e:
        print(f"Emergency cleanup error: {e}")

def background_health_monitor():
    """Background thread to monitor health continuously"""
    while True:
        try:
            health = check_system_health()
            if health['status'] != 'healthy':
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Health Status: {health['status']}")
                for warning in health['warnings']:
                    print(f"[{timestamp}] WARNING: {warning}")
            time.sleep(HEALTH_CHECK_INTERVAL)
        except Exception as e:
            print(f"Health monitor error: {e}")
            time.sleep(60)

# ✅ SMART WEBSOCKET EVENT HANDLERS

@socketio.on('connect')
def handle_connect():
    """Smart connection handling with prioritization"""
    user_id = session.get('user_id')
    username = session.get('user_name')
    
    if not user_id or not username:
        print("❌ Unauthorized WebSocket connection")
        return False
    
    connection_status = smart_connection_management()
    
    if connection_status == 'need_cleanup':
        cleanup_inactive_users()
        
        if len(active_users) >= MAX_TOTAL_CAPACITY:
            emit('connection_queued', {
                'position': len(active_users) - MAX_TOTAL_CAPACITY + 1,
                'message': 'High traffic! You\'ll be connected automatically in a moment.',
                'retry_delay': 15
            })
            return False
    
    # Add user to active users
    active_users[user_id] = {
        'username': username,
        'sid': request.sid,
        'last_seen': time.time(),
        'connect_time': time.time(),
        'priority': 'normal'
    }
    
    join_room(f"user_{user_id}")
    
    if connection_status == 'degraded':
        emit('connection_success', {
            'mode': 'degraded',
            'message': 'Connected in power-save mode. Some real-time features limited.',
            'active_users': len(active_users),
            'features': {
                'realtime_pings': True,
                'live_status': False,
                'activity_feed': False
            }
        })
        print(f"⚡ {username} connected (degraded mode) - Users: {len(active_users)}")
    else:
        emit('connection_success', {
            'mode': 'full',
            'message': 'Connected with all real-time features!',
            'active_users': len(active_users),
            'features': {
                'realtime_pings': True,
                'live_status': True,
                'activity_feed': True
            }
        })
        
        socketio.emit('user_status_update', {
            'user_id': user_id,
            'username': username,
            'status': 'online'
        }, broadcast=True)
        
        print(f"✅ {username} connected (full mode) - Users: {len(active_users)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnecting from WebSocket"""
    user_id = session.get('user_id')
    username = session.get('user_name')
    
    if user_id in active_users:
        session_duration = time.time() - active_users[user_id].get('connect_time', 0)
        del active_users[user_id]
        leave_room(f"user_{user_id}")
        
        socketio.emit('user_status_update', {
            'user_id': user_id,
            'username': username,
            'status': 'offline'
        }, broadcast=True)
        
        print(f"❌ {username} disconnected after {session_duration:.1f}s - Active users: {len(active_users)}")

@socketio.on('ping_user')
def handle_ping_user(data):
    """Handle real-time ping sending with rate limiting"""
    sender_id = session.get('user_id')
    sender_name = session.get('user_name')
    receiver_id = data.get('receiver_id')
    
    if not sender_id or not receiver_id:
        emit('ping_error', {'error': 'Invalid user data'})
        return
    
    if sender_id == receiver_id:
        emit('ping_error', {'error': 'Cannot ping yourself'})
        return
    
    if not check_ping_rate_limit(sender_id):
        emit('ping_error', {
            'error': f'Slow down! Max {MAX_PINGS_PER_MINUTE} pings per minute.'
        })
        print(f"🚫 Rate limited user {sender_name} (ID: {sender_id})")
        return
    
    if sender_id in active_users:
        active_users[sender_id]['last_seen'] = time.time()
    
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
            
            if receiver_id in active_users:
                socketio.emit('new_ping_notification', {
                    'ping_id': ping_id,
                    'sender_id': sender_id,
                    'sender_name': sender_name,
                    'timestamp': datetime.now().isoformat(),
                    'message': f'{sender_name} pinged you!'
                }, room=f"user_{receiver_id}")
            
            emit('ping_success', {
                'message': f'Pinged {data.get("receiver_name", "user")}!',
                'rate_limit_remaining': MAX_PINGS_PER_MINUTE - len(user_ping_rates[sender_id])
            })
            
            print(f"📡 Real-time ping: {sender_name} → {receiver_id}")
        else:
            emit('ping_error', {'error': 'Failed to send ping'})
        
        cur.close()
        
    except Exception as e:
        print(f"Ping database error: {e}")
        emit('ping_error', {'error': 'Database temporarily unavailable'})
    finally:
        if conn:
            release_db_connection(conn)

@socketio.on('get_active_users')
def handle_get_active_users():
    """Send list of currently active users with memory protection"""
    cleanup_memory()
    
    active_list = []
    current_time = time.time()
    
    for user_id, user_data in active_users.items():
        if current_time - user_data['last_seen'] < 120:
            active_list.append({
                'user_id': user_id,
                'username': user_data['username'],
                'last_seen': user_data['last_seen']
            })
    
    emit('active_users_list', {
        'active_users': active_list,
        'server_stats': {
            'active_connections': len(active_users),
            'max_connections': MAX_TOTAL_CAPACITY,
            'server_load': f"{(len(active_users)/MAX_TOTAL_CAPACITY)*100:.1f}%"
        }
    })

# ✅ BACKGROUND CLEANUP TASK
def background_cleanup():
    """Background task to clean up memory and inactive connections"""
    while True:
        try:
            cleanup_memory()
            time.sleep(MEMORY_CLEANUP_INTERVAL)
        except Exception as e:
            print(f"Background cleanup error: {e}")
            time.sleep(60)

cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()
print("🧹 Background cleanup thread started")

# ✅ HEALTH AND CAPACITY MONITORING ENDPOINTS

@app.route('/health')
def health_check():
    """Public health check endpoint"""
    health = check_system_health()
    public_health = {
        'status': health['status'],
        'active_users': health['active_users'],
        'capacity_used': f"{(health['active_users']/MAX_TOTAL_CAPACITY)*100:.1f}%",
        'last_check': datetime.fromtimestamp(health['last_check']).strftime('%H:%M:%S')
    }
    
    if health['status'] == 'healthy':
        return jsonify(public_health), 200
    else:
        return jsonify(public_health), 503

@app.route('/admin/health')
def admin_health():
    """Detailed health check for admins only"""
    if session.get('role') != 'admin':
        return "Unauthorized", 403
    
    health = check_system_health()
    
    db_health = 'unknown'
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        db_health = 'healthy'
        release_db_connection(conn)
    except Exception as e:
        db_health = f'error: {str(e)[:50]}'
    
    detailed_health = {
        **health,
        'database_status': db_health,
        'memory_limit_mb': 512,
        'memory_usage_percent': f"{(health['memory_mb']/512)*100:.1f}%",
        'connection_pool_size': len(active_users),
        'max_connections': MAX_TOTAL_CAPACITY,
        'ping_rates_active': len(user_ping_rates)
    }
    
    return jsonify(detailed_health)

@app.route('/capacity-status')
def capacity_status():
    """Public endpoint to show current capacity"""
    cleanup_memory()
    
    total_users = len(active_users)
    load_percentage = (total_users / MAX_TOTAL_CAPACITY) * 100
    
    if load_percentage < 60:
        status = 'optimal'
        message = '🟢 All systems optimal'
    elif load_percentage < 80:
        status = 'busy'
        message = '🟡 High traffic - all features available'
    else:
        status = 'degraded'
        message = '🟠 Very busy - some features limited'
    
    return jsonify({
        'status': status,
        'message': message,
        'load_percentage': f"{load_percentage:.1f}%",
        'active_users': total_users,
        'capacity': MAX_TOTAL_CAPACITY,
        'features_available': {
            'registration': True,
            'login': True,
            'basic_features': True,
            'realtime_pings': total_users < MAX_TOTAL_CAPACITY,
            'live_status': total_users < MAX_WEBSOCKET_USERS
        }
    })

@app.route('/server-stats')
def server_stats():
    """Admin endpoint to check server health"""
    if session.get('role') != 'admin':
        return "Unauthorized", 403
    
    cleanup_memory()
    
    return jsonify({
        'active_users': len(active_users),
        'max_users': MAX_TOTAL_CAPACITY,
        'websocket_limit': MAX_WEBSOCKET_USERS,
        'load_percentage': f"{(len(active_users)/MAX_TOTAL_CAPACITY)*100:.1f}%",
        'ping_rates': {str(uid): len(pings) for uid, pings in user_ping_rates.items()},
        'memory_status': 'healthy' if len(active_users) < MAX_TOTAL_CAPACITY * 0.8 else 'warning'
    })

# ✅ DATABASE INITIALIZATION

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
                    "CREATE INDEX IF NOT EXISTS idx_pings_receiver_unread ON pings(receiver_id, is_read)",
                    "CREATE INDEX IF NOT EXISTS idx_pings_timestamp ON pings(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_pings_sender ON pings(sender_id)"
                ]
                
                for index in indexes:
                    c.execute(index)
                
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
            columns_to_add = [
                ("social_links", "ALTER TABLE players ADD COLUMN social_links TEXT"),
                ("pin", "ALTER TABLE players ADD COLUMN pin TEXT"),
                ("is_admin", "ALTER TABLE players ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"),
                ("password", "ALTER TABLE players ADD COLUMN password TEXT")
            ]
            
            for column_name, alter_query in columns_to_add:
                c.execute(f"""SELECT column_name FROM information_schema.columns 
                             WHERE table_name='players' AND column_name='{column_name}'""")
                if not c.fetchone():
                    c.execute(alter_query)
                    print(f"{column_name} column added successfully")
                    
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

# ✅ REGISTRATION WITH PRIORITY ACCESS
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
                c.execute("INSERT INTO players (name, country, tier, registered_at, social_links, password) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                    (name, country, tier, registered_at, social_links, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))
                user_id = c.fetchone()[0]
                conn.commit()
                
                session["user_id"] = user_id
                session["user_name"] = name
                session["role"] = "user"
                
                # ✅ PRIORITY ACCESS FOR NEW USERS
                session['new_user_priority'] = True
                session['priority_expires'] = time.time() + 300  # 5 minutes priority
                
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
                        c.execute("""INSERT INTO players (name, country, tier, registered_at, social_links, password, is_admin)
                           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                          (ADMIN_USERNAME, "Global", "God", registered_at, "Admin Account", password, True))
                        admin_id = c.fetchone()[0]
                        conn.commit()
                    else:
                        admin_id = admin_user[0]
                    
                    if remember_me:
                        session.permanent = True
                    
                    session["user_id"] = admin_id
                    session["user_name"] = ADMIN_USERNAME
                    session["role"] = "admin"
                    
                    # ✅ ADMIN PRIORITY ACCESS
                    session['admin_priority'] = True
                    
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
                    c.execute("SELECT COUNT(*) FROM players WHERE name = %s AND id != %s", (new_name, user_id))
                    name_taken = c.fetchone()[0]
                    
                    if name_taken > 0:
                        flash("Username is already taken.", "error")
                    else:
                        c.execute("UPDATE players SET name = %s, country = %s, tier = %s, social_links = %s WHERE id = %s",
                                  (new_name, new_country, new_tier, new_social_links, user_id))
                        conn.commit()
                        session["user_name"] = new_name
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

    columns = ['id', 'username', 'country', 'tier', 'registered_at', 'social_links', 'is_admin']
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

@app.route("/ping/<int:player_id>", methods=["POST"])
def ping_player(player_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    sender_id = session['user_id']
    
    if sender_id == player_id:
        return jsonify({'error': 'Cannot ping yourself'}), 400

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
        
        # Real-time notification via WebSocket
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

# ✅ START HEALTH MONITORING AND SERVER
app.start_time = time.time()
health_thread = threading.Thread(target=background_health_monitor, daemon=True)
health_thread.start()
print("💗 Health monitoring started")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print("🧠 Smart Load Management enabled!")
    print(f"📊 WebSocket users: {MAX_WEBSOCKET_USERS}")
    print(f"📊 Total capacity: {MAX_TOTAL_CAPACITY}")  
    print(f"🔒 Reserved for new users: {PRIORITY_RESERVE}")
    print("✅ No more 'Server Busy' messages for new registrations!")
    print("💗 Health monitoring active!")
    socketio.run(app, host="0.0.0.0", port=port, debug=True)