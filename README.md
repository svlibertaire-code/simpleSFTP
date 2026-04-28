# simpleSFTP

A secure web-based SFTP file manager built with Flask and Python. Browse, upload, download, and manage files on your local machine and remote VPS through a clean dual-pane interface — with user authentication, encrypted credential storage, and connection profiles.

## Features

- **User authentication**: Login/register with bcrypt-hashed passwords
- **Encrypted credentials**: SFTP passwords encrypted with your app password (PBKDF2 + Fernet)
- **Connection profiles**: Save frequently-used SFTP connections, connect with one click
- **Audit logging**: Every login/logout recorded with IP, timestamp, success/fail
- **Remember me**: Persistent sessions with secure signed cookies
- **Dual-pane interface**: Local filesystem on the left, remote SFTP on the right
- **SFTP operations**: Connect via password or SSH key, browse directories, upload/download/delete/mkdir
- **Dark theme**: Easy on the eyes

## Quick Start

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py

# Open browser at http://localhost:5001
```

## Usage

### First time
1. Go to `/login` and register an account
2. Log in (optionally check "Remember me")

### Connect to a server
**Option A — Manual:**
1. Enter host, port, username, password (or SSH key path)
2. Click **Connect**

**Option B — Saved Profile:**
1. Go to **Connection Profiles**
2. Add a new profile (credentials are encrypted with your password)
3. Click **Connect** on any saved profile

### Transfer files
- Double-click directories to navigate
- Select a file and click **To Local** or **To Remote**

## Security Architecture

| Layer | Implementation |
|-------|---------------|
| App passwords | bcrypt with salt |
| SFTP credentials | PBKDF2-derived key + Fernet symmetric encryption |
| Sessions | Flask signed cookies, optional 30-day persistent token |
| Audit | SQLite log of all auth events with IP and timestamp |

**Important:** The encryption key for stored SFTP credentials is derived from your app password. If you change your password, saved profiles will need to be re-created.

## Project Structure

```
simpleSFTP/
├── app.py                  # Flask backend
├── templates/
│   ├── index.html          # Main file manager UI
│   ├── login.html          # Auth page (login/register)
│   └── profiles.html       # Connection profiles manager
├── requirements.txt        # Python dependencies
├── .gitignore             # Excludes venv, db, cache
└── README.md              # This file
```

## Production Notes

- Run behind **nginx reverse proxy** with HTTPS
- Set `SECRET_KEY` environment variable for session security
- Consider restricting to **Tailscale VPN** or localhost
- SSH private keys should have permissions `600`

## Roadmap / TODO

- [ ] Local file delete and mkdir
- [ ] Drag-and-drop file upload
- [ ] Progress bars for large transfers
- [ ] Multiple file selection
- [ ] SSH key passphrase support
- [ ] Rate limiting / brute force protection

## License

MIT
