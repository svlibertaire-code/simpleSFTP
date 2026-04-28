# simpleSFTP

A minimal web-based SFTP file manager built with Flask and Python. Browse, upload, download, and manage files on your local machine and remote VPS through a clean dual-pane interface.

## Features

- **Dual-pane interface**: Local filesystem on the left, remote SFTP on the right
- **SFTP operations**: Connect via password or SSH key, browse directories, upload/download/delete
- **Dark theme**: Easy on the eyes
- **No JavaScript framework**: Plain vanilla JS for simplicity

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py

# Open browser at http://localhost:5000
```

## Usage

1. Enter your VPS host, port (default 22), username, and password
2. Click **Connect**
3. Browse remote files, double-click directories to navigate
4. Select a file and click **To Local** or **To Remote** to transfer

## Security Notes

- Credentials are stored in-memory per session only
- For production, run behind a reverse proxy (nginx) with HTTPS
- Consider restricting to localhost or Tailscale VPN
- SSH private keys should have appropriate permissions (600)

## Project Structure

```
simpleSFTP/
├── app.py              # Flask backend with SFTP via paramiko
├── templates/
│   └── index.html      # Single-page UI
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Roadmap / TODO

- [ ] Local file delete and mkdir
- [ ] Drag-and-drop file upload
- [ ] Progress bars for large transfers
- [ ] Multiple file selection
- [ ] SSH key passphrase support
- [ ] Connection profiles (save hosts)

## License

MIT
