"""
Secure Authentication System
Technologies: Python (Flask, bcrypt, PyJWT), SQLite
All encryption + token generation happens locally — no external API/service needed.
"""

import os
import sqlite3
import jwt
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production-9f8a7b6c')
CORS(app)
bcrypt = Bcrypt(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'auth.db')

JWT_EXPIRY_MINUTES = 30
JWT_REFRESH_DAYS = 7
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            success INTEGER,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_attempt(username, success, ip='local'):
    conn = get_db()
    conn.execute('INSERT INTO login_log (username, success, ip_address) VALUES (?,?,?)',
                 (username, int(success), ip))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Returns (is_valid, message)"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain a number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain a special character"
    return True, "OK"

def password_strength_score(password):
    """0-100 score for UI strength meter"""
    score = 0
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 15
    if re.search(r'[A-Z]', password): score += 15
    if re.search(r'[a-z]', password): score += 15
    if re.search(r'[0-9]', password): score += 15
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 20
    return min(score, 100)

# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────

def generate_token(user_id, username, expiry_minutes=JWT_EXPIRY_MINUTES):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_refresh_token(user_id):
    payload = {
        'user_id': user_id,
        'type': 'refresh',
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_DAYS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except jwt.InvalidTokenError:
        return None, 'Invalid token'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401

        token = auth_header.split(' ')[1]
        payload, error = decode_token(token)
        if error:
            return jsonify({'error': error}), 401

        conn = get_db()
        user = conn.execute('SELECT id, username, email FROM users WHERE id=?',
                            (payload['user_id'],)).fetchone()
        conn.close()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        request.current_user = dict(user)
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# ROUTES — PAGES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

# ─────────────────────────────────────────────
# ROUTES — AUTH API
# ─────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400

    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username=? OR email=?',
                            (username, email)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Username or email already registered'}), 409

    # bcrypt hash happens HERE, locally, on your machine
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)',
                (username, email, password_hash))
    conn.commit()
    user_id = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()['id']
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Account created successfully',
        'user': {'id': user_id, 'username': username, 'email': email}
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=? OR email=?',
                        (username, username)).fetchone()

    if not user:
        log_attempt(username, False)
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    user = dict(user)

    # Check lockout
    if user['locked_until']:
        locked_until = datetime.fromisoformat(user['locked_until'])
        if datetime.now() < locked_until:
            remaining = int((locked_until - datetime.now()).total_seconds() / 60) + 1
            conn.close()
            return jsonify({'error': f'Account locked. Try again in {remaining} minutes'}), 423

    # bcrypt verification happens HERE, locally
    if not bcrypt.check_password_hash(user['password_hash'], password):
        attempts = user['failed_attempts'] + 1
        locked_until = None
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()

        conn.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?',
                    (attempts, locked_until, user['id']))
        conn.commit()
        conn.close()
        log_attempt(username, False)

        if locked_until:
            return jsonify({'error': f'Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes'}), 423
        return jsonify({'error': f'Invalid credentials. {MAX_LOGIN_ATTEMPTS - attempts} attempts remaining'}), 401

    # Success — reset failed attempts, update last login
    conn.execute('UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?',
                (datetime.now().isoformat(), user['id']))
    conn.commit()
    conn.close()
    log_attempt(username, True)

    # JWT generation happens HERE, locally
    access_token = generate_token(user['id'], user['username'])
    refresh_token = generate_refresh_token(user['id'])

    return jsonify({
        'success': True,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_in': JWT_EXPIRY_MINUTES * 60,
        'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}
    })

@app.route('/api/refresh', methods=['POST'])
def refresh():
    data = request.json or {}
    refresh_token = data.get('refresh_token', '')
    payload, error = decode_token(refresh_token)
    if error or payload.get('type') != 'refresh':
        return jsonify({'error': 'Invalid refresh token'}), 401

    conn = get_db()
    user = conn.execute('SELECT id, username FROM users WHERE id=?', (payload['user_id'],)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 401

    new_access_token = generate_token(user['id'], user['username'])
    return jsonify({'access_token': new_access_token, 'expires_in': JWT_EXPIRY_MINUTES * 60})

@app.route('/api/me', methods=['GET'])
@token_required
def me():
    conn = get_db()
    user = conn.execute('SELECT username, email, created_at, last_login FROM users WHERE id=?',
                        (request.current_user['id'],)).fetchone()
    conn.close()
    return jsonify(dict(user))

@app.route('/api/check_password_strength', methods=['POST'])
def check_strength():
    data = request.json or {}
    password = data.get('password', '')
    score = password_strength_score(password)
    valid, msg = validate_password(password) if password else (False, '')
    label = 'Weak' if score < 40 else 'Fair' if score < 70 else 'Strong' if score < 100 else 'Very Strong'
    return jsonify({'score': score, 'label': label, 'valid': valid, 'message': msg})

@app.route('/api/login_history', methods=['GET'])
@token_required
def login_history():
    conn = get_db()
    logs = conn.execute(
        'SELECT success, ip_address, timestamp FROM login_log WHERE username=? ORDER BY timestamp DESC LIMIT 10',
        (request.current_user['username'],)
    ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    # Stateless JWT — client just discards the token.
    # For true server-side invalidation, you'd maintain a token blocklist table.
    return jsonify({'success': True, 'message': 'Logged out'})

if __name__ == '__main__':
    init_db()
    print("🔐 Secure Authentication System starting...")
    print("🔑 bcrypt + PyJWT — all processing local, no external API")
    print("🌐 Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
