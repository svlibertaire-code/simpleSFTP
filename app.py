from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, make_response
from flask_bcrypt import Bcrypt
import paramiko
import os
import io
import json
import stat
import sqlite3
import secrets
import hashlib
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
bcrypt = Bcrypt(app)

# Thread pool for blocking SFTP operations
executor = ThreadPoolExecutor(max_workers=4)

# In-memory connection store (per session)
connections = {}

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'simplesftp.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Saved connections (encrypted)
    c.execute('''
        CREATE TABLE IF NOT EXISTS saved_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            encrypted_password TEXT,
            encrypted_key_data TEXT,
            key_filename TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Login audit log
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            action TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Encryption helpers
def get_fernet(password):
    """Derive encryption key from user password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'simplesftp_salt_v1',  # In production, use per-user random salt stored in DB
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_data(data, password):
    if not data:
        return None
    f = get_fernet(password)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, password):
    if not encrypted_data:
        return None
    try:
        f = get_fernet(password)
        return f.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

# Auth decorators
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

def require_connection(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = session.get('session_id')
        if not session_id or session_id not in connections:
            return jsonify({'error': 'Not connected. POST /connect first.'}), 401
        return f(*args, **kwargs)
    return decorated

# Logging
def log_auth(username, success, action='login', user_id=None, details=None):
    """Log authentication events."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', '')
    c.execute('''
        INSERT INTO login_log (user_id, username, ip_address, user_agent, action, success, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, username, ip, ua, action, success, details))
    conn.commit()
    conn.close()

# SFTP helpers
def get_sftp_client(session_id):
    if session_id not in connections:
        return None
    conn = connections[session_id]
    if conn['ssh'].get_transport() is None or not conn['ssh'].get_transport().is_active():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=conn['host'],
            port=conn['port'],
            username=conn['username'],
            password=conn.get('password'),
            key_filename=conn.get('key_filename'),
            timeout=10,
            look_for_keys=True
        )
        conn['ssh'] = ssh
        conn['sftp'] = ssh.open_sftp()
    return conn['sftp']


# ---- AUTH ROUTES ----

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    
    if row and bcrypt.check_password_hash(row[1], password):
        session['user_id'] = row[0]
        session['username'] = username
        session['password'] = password  # Store plaintext temporarily for credential encryption
        session.permanent = remember
        log_auth(username, True, 'login', user_id=row[0])
        
        resp = make_response(jsonify({'success': True, 'redirect': '/'}))
        if remember:
            token = secrets.token_urlsafe(32)
            resp.set_cookie('remember_token', token, max_age=30*24*60*60, httponly=True, samesite='Lax')
        return resp
    else:
        log_auth(username, False, 'login', details='Invalid credentials')
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password or len(password) < 6:
        return jsonify({'error': 'Username required, password must be 6+ chars'}), 400
    
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
        user_id = c.lastrowid
        conn.commit()
        log_auth(username, True, 'register', user_id=user_id)
        return jsonify({'success': True, 'message': 'User created. Please log in.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()


@app.route('/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Clear SFTP connection
    session_id = session.get('session_id')
    if session_id and session_id in connections:
        conn = connections.pop(session_id, None)
        if conn:
            try:
                conn['sftp'].close()
                conn['ssh'].close()
            except Exception:
                pass
    
    session.clear()
    resp = make_response(jsonify({'success': True}))
    resp.set_cookie('remember_token', '', max_age=0)
    
    if username:
        log_auth(username, True, 'logout', user_id=user_id)
    return resp


@app.route('/auth/status')
def auth_status():
    if 'user_id' in session:
        return jsonify({'authenticated': True, 'username': session.get('username')})
    return jsonify({'authenticated': False})


# ---- MAIN APP ----

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


# ---- CONNECTION PROFILES PAGE ----

@app.route('/profiles')
def profiles_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profiles.html')


@app.route('/api/profiles', methods=['GET'])
@require_login
def list_profiles():
    """List saved connection profiles for current user."""
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, name, host, port, username, key_filename, created_at
        FROM saved_connections
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    rows = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'profiles': [
            {
                'id': r[0],
                'name': r[1],
                'host': r[2],
                'port': r[3],
                'username': r[4],
                'key_filename': r[5],
                'created_at': r[6]
            }
            for r in rows
        ]
    })


@app.route('/api/profiles', methods=['POST'])
@require_login
def create_profile():
    """Save a new connection profile with encrypted credentials."""
    data = request.get_json() or request.form
    user_id = session['user_id']
    
    name = data.get('name', '').strip()
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')
    
    if not all([name, host, username]):
        return jsonify({'error': 'Name, host, and username required'}), 400
    
    # Encrypt credentials with user's app password
    app_password = session.get('password')
    if not app_password:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401
    
    encrypted_password = encrypt_data(password, app_password)
    encrypted_key_data = None  # For future: upload key file content
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO saved_connections (user_id, name, host, port, username, encrypted_password, encrypted_key_data, key_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, name, host, port, username, encrypted_password, encrypted_key_data, key_filename))
        profile_id = c.lastrowid
        conn.commit()
        return jsonify({'success': True, 'id': profile_id, 'message': f'Profile "{name}" saved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/profiles/<int:profile_id>', methods=['GET'])
@require_login
def get_profile(profile_id):
    """Get a single profile (without decrypted credentials)."""
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, name, host, port, username, key_filename, created_at
        FROM saved_connections
        WHERE id = ? AND user_id = ?
    ''', (profile_id, user_id))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Profile not found'}), 404
    
    return jsonify({
        'success': True,
        'profile': {
            'id': row[0],
            'name': row[1],
            'host': row[2],
            'port': row[3],
            'username': row[4],
            'key_filename': row[5],
            'created_at': row[6]
        }
    })


@app.route('/api/profiles/<int:profile_id>', methods=['PUT'])
@require_login
def update_profile(profile_id):
    """Update a connection profile with re-encrypted credentials."""
    data = request.get_json() or request.form
    user_id = session['user_id']
    
    name = data.get('name', '').strip()
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')
    
    if not all([name, host, username]):
        return jsonify({'error': 'Name, host, and username required'}), 400
    
    app_password = session.get('password')
    if not app_password:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401
    
    encrypted_password = encrypt_data(password, app_password)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        UPDATE saved_connections
        SET name = ?, host = ?, port = ?, username = ?, encrypted_password = ?, key_filename = ?
        WHERE id = ? AND user_id = ?
    ''', (name, host, port, username, encrypted_password, key_filename, profile_id, user_id))
    updated = c.rowcount
    conn.commit()
    conn.close()
    
    if updated:
        return jsonify({'success': True, 'message': f'Profile "{name}" updated'})
    return jsonify({'error': 'Profile not found'}), 404


@app.route('/api/profiles/<int:profile_id>', methods=['DELETE'])
@require_login
def delete_profile(profile_id):
    """Delete a connection profile."""
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM saved_connections WHERE id = ? AND user_id = ?', (profile_id, user_id))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    
    if deleted:
        return jsonify({'success': True, 'message': 'Profile deleted'})
    return jsonify({'error': 'Profile not found'}), 404


@app.route('/connection/status', methods=['GET'])
@require_login
def connection_status():
    """Check if there's an active SFTP connection for this session."""
    session_id = session.get('session_id')
    conn = connections.get(session_id)
    if conn:
        return jsonify({
            'connected': True,
            'host': conn['host'],
            'port': conn['port'],
            'username': conn['username'],
            'cwd': conn['cwd']
        })
    return jsonify({'connected': False})

@app.route('/api/profiles/<int:profile_id>/connect', methods=['POST'])
@require_login
def connect_from_profile(profile_id):
    """Connect using a saved profile — decrypts credentials on the fly."""
    user_id = session['user_id']
    app_password = session.get('password')
    if not app_password:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT name, host, port, username, encrypted_password, key_filename
        FROM saved_connections
        WHERE id = ? AND user_id = ?
    ''', (profile_id, user_id))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Profile not found'}), 404
    
    name, host, port, username, encrypted_password, key_filename = row
    password = decrypt_data(encrypted_password, app_password)
    
    # Now connect with decrypted credentials
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=10,
            look_for_keys=True
        )
        sftp = ssh.open_sftp()
        
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
        connections[session_id] = {
            'ssh': ssh,
            'sftp': sftp,
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'key_filename': key_filename,
            'cwd': '/'
        }
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': f'Connected to {host}:{port} as {username} (via profile "{name}")'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---- SFTP CONNECTION (manual) ----

@app.route('/connect', methods=['POST'])
@require_login
def connect():
    data = request.get_json() or request.form
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')
    
    if not all([host, username]) or (not password and not key_filename):
        return jsonify({'error': 'Host, username, and either password or key file required'}), 400
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=10,
            look_for_keys=True
        )
        sftp = ssh.open_sftp()
        
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
        connections[session_id] = {
            'ssh': ssh,
            'sftp': sftp,
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'key_filename': key_filename,
            'cwd': '/'
        }
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': f'Connected to {host}:{port} as {username}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/disconnect', methods=['POST'])
@require_login
@require_connection
def disconnect():
    session_id = session.get('session_id')
    conn = connections.pop(session_id, None)
    if conn:
        try:
            conn['sftp'].close()
            conn['ssh'].close()
        except Exception:
            pass
    session.pop('session_id', None)
    return jsonify({'success': True})


# ---- REMOTE FILE OPS ----

@app.route('/remote/list', methods=['POST'])
@require_login
@require_connection
def remote_list():
    data = request.get_json() or request.form
    path = data.get('path', '/')
    sftp = get_sftp_client(session.get('session_id'))
    try:
        entries = sftp.listdir_attr(path)
        files = []
        for entry in entries:
            files.append({
                'name': entry.filename,
                'size': entry.st_size,
                'mode': entry.st_mode,
                'is_dir': stat.S_ISDIR(entry.st_mode),
                'mtime': entry.st_mtime
            })
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return jsonify({'success': True, 'path': path, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/download', methods=['POST'])
@require_login
@require_connection
def remote_download():
    data = request.get_json() or request.form
    remote_path = data.get('remote_path')
    local_path = data.get('local_path')
    if not remote_path or not local_path:
        return jsonify({'error': 'remote_path and local_path required'}), 400
    sftp = get_sftp_client(session.get('session_id'))
    try:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        sftp.get(remote_path, local_path)
        return jsonify({'success': True, 'message': f'Downloaded to {local_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/upload', methods=['POST'])
@require_login
@require_connection
def remote_upload():
    data = request.get_json() or request.form
    local_path = data.get('local_path')
    remote_path = data.get('remote_path')
    if not local_path or not remote_path:
        return jsonify({'error': 'local_path and remote_path required'}), 400
    if not os.path.exists(local_path):
        return jsonify({'error': f'Local file not found: {local_path}'}), 404
    sftp = get_sftp_client(session.get('session_id'))
    try:
        sftp.put(local_path, remote_path)
        return jsonify({'success': True, 'message': f'Uploaded to {remote_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/delete', methods=['POST'])
@require_login
@require_connection
def remote_delete():
    data = request.get_json() or request.form
    remote_path = data.get('remote_path')
    is_dir = data.get('is_dir', False)
    if not remote_path:
        return jsonify({'error': 'remote_path required'}), 400
    sftp = get_sftp_client(session.get('session_id'))
    try:
        if is_dir:
            sftp.rmdir(remote_path)
        else:
            sftp.remove(remote_path)
        return jsonify({'success': True, 'message': f'Deleted {remote_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/mkdir', methods=['POST'])
@require_login
@require_connection
def remote_mkdir():
    data = request.get_json() or request.form
    remote_path = data.get('remote_path')
    if not remote_path:
        return jsonify({'error': 'remote_path required'}), 400
    sftp = get_sftp_client(session.get('session_id'))
    try:
        sftp.mkdir(remote_path)
        return jsonify({'success': True, 'message': f'Created {remote_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/rename', methods=['POST'])
@require_login
@require_connection
def remote_rename():
    data = request.get_json() or request.form
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    if not old_path or not new_path:
        return jsonify({'error': 'old_path and new_path required'}), 400
    sftp = get_sftp_client(session.get('session_id'))
    try:
        sftp.rename(old_path, new_path)
        return jsonify({'success': True, 'message': f'Renamed to {new_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---- LOCAL FILE OPS ----

@app.route('/local/list', methods=['POST'])
@require_login
def local_list():
    data = request.get_json() or request.form
    path = data.get('path', os.path.expanduser('~'))
    try:
        entries = os.listdir(path)
        files = []
        for name in entries:
            full_path = os.path.join(path, name)
            stat_info = os.stat(full_path)
            files.append({
                'name': name,
                'size': stat_info.st_size,
                'is_dir': os.path.isdir(full_path),
                'mtime': stat_info.st_mtime
            })
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return jsonify({'success': True, 'path': path, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/local/download')
@require_login
def local_download():
    path = request.args.get('path')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(path, as_attachment=True)


@app.route('/local/upload', methods=['POST'])
@require_login
def local_upload():
    target_dir = request.form.get('path', os.path.expanduser('~'))
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    filepath = os.path.join(target_dir, file.filename)
    file.save(filepath)
    return jsonify({'success': True, 'message': f'Saved to {filepath}'})


@app.route('/local/delete', methods=['POST'])
@require_login
def local_delete():
    data = request.get_json() or request.form
    path = data.get('path')
    is_dir = data.get('is_dir', False)
    if not path:
        return jsonify({'error': 'path required'}), 400
    try:
        if is_dir:
            os.rmdir(path)
        else:
            os.remove(path)
        return jsonify({'success': True, 'message': f'Deleted {path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/local/rename', methods=['POST'])
@require_login
def local_rename():
    data = request.get_json() or request.form
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    if not old_path or not new_path:
        return jsonify({'error': 'old_path and new_path required'}), 400
    try:
        os.rename(old_path, new_path)
        return jsonify({'success': True, 'message': f'Renamed to {new_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/local/mkdir', methods=['POST'])
@require_login
def local_mkdir():
    data = request.get_json() or request.form
    path = data.get('path')
    if not path:
        return jsonify({'error': 'path required'}), 400
    try:
        os.mkdir(path)
        return jsonify({'success': True, 'message': f'Created {path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---- ADMIN / AUDIT ----

@app.route('/admin/login-log')
@require_login
def login_log():
    """Return login audit log for the current user."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    user_id = session.get('user_id')
    
    c.execute('''
        SELECT username, action, success, ip_address, timestamp, details
        FROM login_log
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 100
    ''', (user_id,))
    rows = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'logs': [
            {
                'username': r[0],
                'action': r[1],
                'success': bool(r[2]),
                'ip': r[3],
                'timestamp': r[4],
                'details': r[5]
            }
            for r in rows
        ]
    })


if __name__ == '__main__':
    # Bind to Tailscale IP only for security
    TAILSCALE_IP = '100.90.68.31'
    app.run(host=TAILSCALE_IP, port=5001, debug=True)
