from flask import Flask, render_template, request, jsonify, send_file, session
import paramiko
import os
import io
import json
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Thread pool for blocking SFTP operations
executor = ThreadPoolExecutor(max_workers=4)

# In-memory connection store (per session)
# In production, use a proper credential vault
connections = {}


def get_sftp_client(session_id):
    """Retrieve or create an SFTP client for this session."""
    if session_id not in connections:
        return None
    conn = connections[session_id]
    # Check if transport is still alive
    if conn['ssh'].get_transport() is None or not conn['ssh'].get_transport().is_active():
        # Reconnect
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=conn['host'],
            port=conn['port'],
            username=conn['username'],
            password=conn.get('password'),
            key_filename=conn.get('key_filename'),
            timeout=10
        )
        conn['ssh'] = ssh
        conn['sftp'] = ssh.open_sftp()
    return conn['sftp']


def require_connection(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = session.get('session_id')
        if not session_id or session_id not in connections:
            return jsonify({'error': 'Not connected. POST /connect first.'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/connect', methods=['POST'])
def connect():
    """Establish SFTP connection to remote host."""
    data = request.get_json() or request.form
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')  # path to private key on server

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
            look_for_keys=False
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
@require_connection
def disconnect():
    """Close SFTP connection."""
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


@app.route('/remote/list', methods=['POST'])
@require_connection
def remote_list():
    """List files in a remote directory."""
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
                'is_dir': paramiko.S_ISDIR(entry.st_mode),
                'mtime': entry.st_mtime
            })
        # Sort: directories first, then alphabetical
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return jsonify({'success': True, 'path': path, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/download', methods=['POST'])
@require_connection
def remote_download():
    """Download a file from remote to local (Flask server)."""
    data = request.get_json() or request.form
    remote_path = data.get('remote_path')
    local_path = data.get('local_path')

    if not remote_path or not local_path:
        return jsonify({'error': 'remote_path and local_path required'}), 400

    sftp = get_sftp_client(session.get('session_id'))
    try:
        # Ensure local directory exists
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        sftp.get(remote_path, local_path)
        return jsonify({'success': True, 'message': f'Downloaded to {local_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remote/upload', methods=['POST'])
@require_connection
def remote_upload():
    """Upload a file from local (Flask server) to remote."""
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
@require_connection
def remote_delete():
    """Delete a file or directory on remote."""
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
@require_connection
def remote_mkdir():
    """Create a directory on remote."""
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


# ---- Local filesystem routes ----

@app.route('/local/list', methods=['POST'])
def local_list():
    """List files in a local directory."""
    data = request.get_json() or request.form
    path = data.get('path', os.path.expanduser('~'))

    try:
        entries = os.listdir(path)
        files = []
        for name in entries:
            full_path = os.path.join(path, name)
            stat = os.stat(full_path)
            files.append({
                'name': name,
                'size': stat.st_size,
                'is_dir': os.path.isdir(full_path),
                'mtime': stat.st_mtime
            })
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return jsonify({'success': True, 'path': path, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/local/download')
def local_download():
    """Download a local file through browser."""
    path = request.args.get('path')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(path, as_attachment=True)


@app.route('/local/upload', methods=['POST'])
def local_upload():
    """Upload a file to local directory."""
    target_dir = request.form.get('path', os.path.expanduser('~'))
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    filepath = os.path.join(target_dir, file.filename)
    file.save(filepath)
    return jsonify({'success': True, 'message': f'Saved to {filepath}'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
