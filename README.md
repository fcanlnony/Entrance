# Entrance Tools

Default documentation is in English. For Simplified Chinese, see [doc/README_CN.md](doc/README_CN.md).

Web-based server management tools with SSH terminal access, local shell terminal access, VNC remote desktop, WebSerial terminal support, flashing/debugging workflows, and SFTP file management. The UI follows Microsoft Fluent Design, supports light/dark themes, and includes both Chinese and English interface modes.
![Screenshot](doc/screenshot.png)

## Friend Links

- EK-OmniProbe https://github.com/EmbeddedKitOrg/EK-OmniProbe
- Clion-Waveform-Plotter https://github.com/Szturin/Clion-Waveform-Plotter

## Features

### SSH Terminal
- Real-time SSH connections over WebSocket
- xterm.js terminal emulator
- Automatic terminal resize support
- Real-time connection status display
- **System Stats** - Real-time performance monitoring
  - Starts collecting automatically after connection and shows CPU / memory / disk I/O in the status bar
  - Click the status bar to expand a Chart.js line chart with historical trends
  - Based on `/proc/stat`, `/proc/meminfo`, and `/proc/diskstats`
  - 1-second sampling interval, up to 60 data points
- **Process Management (TOP)** - Real-time process monitoring panel
  - Collects process data automatically after connection and shows process count / running count / load
  - Click the status bar to expand the full process list
  - Displays PID, user, CPU%, memory%, VSZ, RSS, state, time, and command
  - Sort by CPU / memory / PID / time
  - Configurable row count (15/30/50/100)
  - **Kill Process** - Supports multiple signals
    - SIGTERM (15) - graceful termination
    - SIGKILL (9) - force kill
    - SIGINT (2) - interrupt signal
    - SIGHUP (1) - hangup / reload configuration
    - SIGSTOP (19) - pause process
    - SIGCONT (18) - continue process
- **Docker Monitoring** - Container resource panel
  - Detects Docker automatically on the remote host and shows container count / CPU / memory in the status bar
  - Click the status bar to expand detailed metrics
  - SVG ring charts for CPU, MEM, NET I/O, and BLOCK I/O
  - **Total mode** - aggregate resource usage across all containers
  - **Single mode** - select a container on the left and show detailed metrics on the right
  - Based on `docker stats --no-stream`, sampled every 3 seconds
  - Handles missing Docker installations or permission issues automatically

### Local Shell Terminal
- Access the server's local terminal in the browser
- Linux/macOS uses `script + child_process`
- Windows uses local `OpenSSH Server` plus a `127.0.0.1` SSH session to get PTY/ConPTY semantics without `node-pty`
- Supports Linux, macOS, and Windows
- Only shells found in PATH are allowed (bash/zsh/fish/cmd/powershell, etc.)
- 256-color support
- Automatic terminal resize

### VNC Remote Desktop
- noVNC-based remote desktop connection
- WebSocket proxy support
- Fullscreen support
- Real-time screen streaming

### WebSerial Terminal
- Native browser serial communication via the Web Serial API
- Custom baud rate configuration
- xterm.js terminal output
- Supports Linux `/dev/tty*`, macOS `/dev/cu.*`, and Windows `COM*` ports
- **Real-time Waveform Visualization**
  - Automatically detects `Variable:Value` format data
  - Creates multi-variable curves dynamically
  - Sliding window display (50-1000 samples configurable)
  - Real-time legend values
  - Pause / resume / clear support
- **Stat Chart Visualization**
  - Supports `var:[a:2, b:3, c:5, d:6]` format data
  - Different subkeys get distinct colors automatically
  - Supports multiple variables shown at once
- **Demo Mode**
  - Test waveform and stat chart features without a real serial device
- Useful for hardware debugging, embedded development, and ADC data visualization

### Flash & Debug
- Supports local `OpenOCD`, `pyOCD`, and `probe-rs` flashing/debugging tools
- Select probe, target chip/config, speed, and extra arguments from the GUI, with live CLI preview and logs
- Upload firmware files to a temporary directory on the current Entrance host before flashing
- `OpenOCD` supports automatic target/interface config discovery; `pyOCD` and `probe-rs` support automatic probe enumeration
- **Target Search Autocomplete**
  - `OpenOCD` can search `target/*.cfg` and `interface/*.cfg`
  - `pyOCD` can search its built-in target catalog
  - `probe-rs` can search the chip catalog returned by `probe-rs chip list`
  - Supports prefix matches, substring matches, and lightweight fuzzy matching while still allowing manual input
  - Tool-specific placeholders, helper hints, detected-candidate counters, and fallback probe/catalog messages follow the current UI language automatically
- **Admin/root Elevation Request**
  - Linux prefers `pkexec`, then falls back to `sudo + zenity/kdialog`
  - macOS uses `sudo + osascript`
  - Windows prefers `gsudo`, then falls back to system `sudo`
- Only administrators can start local flashing or debugging tasks

### SFTP File Management
- Remote file browsing and navigation
- Back / forward / parent directory navigation
- File and folder upload with drag-and-drop support
- Single-file download
- Multi-file or folder ZIP download
- Create new folders
- Delete files and folders
- Ctrl+click multi-select

### UI Features
- Microsoft Fluent Design
- Light / dark theme toggle
- **Material You Color Schemes** - 6 optional accent themes
  - Default (neutral graphite)
  - Sakura (soft petals)
  - Ocean (clear tide)
  - Forest (moss grove)
  - Twilight (soft dusk)
  - Amber (warm sunset)
- **UI Internationalization**
  - English by default, with instant switching between Chinese and English
  - A dedicated language card is shown below the color scheme card in Settings
  - Language choice is persisted in browser local storage
- Acrylic effects
- Reveal highlight effect
- Responsive sidebar

### Settings
- **Change Password** - users can change their own login password in Settings (Argon2id hashed)
- When `ENTRANCE_DESKTOP_NOLOGIN=1`, password changes are disabled and a notice is shown
- **Private Network Allowlist** - administrators can open a dedicated card below the password card in Settings to manage private CIDR ranges for SSH, SFTP, and VNC
- **Color Scheme Switching** - choose a Material You style accent scheme in Settings, saved automatically
- **Language Switching** - switch the UI language from a dedicated card below the color scheme card; default is English, currently supports Chinese and English

## Quick Start

### Requirements
- Node.js >= 16.0.0
- npm

### Run Locally

```bash
# Clone the repository
git clone git@github.com:fcanlnony/Entrance.git
cd Entrance

# Install dependencies
npm install

# Start the service
npm start
```

Visit http://localhost:3000 and sign in to enter the dashboard.

To use a different port, use an environment variable or CLI flag:

```bash
PORT=4000 npm start
# or
npm start -- --port 4000
```

Then open `http://localhost:4000`.

### Minimal Run Example

```bash
mkdir -p ./.data
[ -f ./.data/auth_secret ] || openssl rand -base64 32 > ./.data/auth_secret

export ENTRANCE_DATA_DIR="$(pwd)/.data"
export AUTH_SECRET="$(tr -d '\n' < ./.data/auth_secret)"
npm start
```

This example pins runtime data to `./.data` and lets Entrance generate and reuse the SSH credential encryption key in `./.data/.ssh_password_key`. Do not regenerate `SSH_PASSWORD_KEY` before each restart, or existing allowlists, passwords, and private keys will become undecryptable.

The default account is `admin/admin` on first boot.

### Docker Example

```bash
# Build the image
docker build -t entrance-tools .

# Create runtime resources once
docker volume create entrance-tools-data
[ -f ./.docker-auth_secret ] || openssl rand -base64 32 > ./.docker-auth_secret

# Run with port mapping and persistent data
docker run -d --name entrance-tools \
  -p 3000:3000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

To expose a different port, for example `4000`, change both the internal listen port and the host port mapping:

```bash
docker run -d --name entrance-tools \
  -p 4000:4000 \
  -e PORT=4000 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.docker-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

`SSH_PASSWORD_KEY` is intentionally omitted here. The container generates it once in the persistent volume at `/data/.ssh_password_key` and keeps reusing it. As long as the volume remains, rebuilding the container will not break historical encrypted data.

### Docker Compose Example

The repository already includes `compose.yml`, which mounts host `./data` into container `/data` by default:

```bash
mkdir -p ./data
[ -f ./.compose-auth_secret ] || openssl rand -base64 32 > ./.compose-auth_secret

export AUTH_SECRET="$(tr -d '\n' < ./.compose-auth_secret)"
docker compose up -d --build
```

To use a different port, set `PORT` before startup:

```bash
export PORT=4000
docker compose up -d --build
```

Likewise, do not regenerate `SSH_PASSWORD_KEY` before every `docker compose up`. If you keep `./data`, Entrance will automatically reuse `./data/.ssh_password_key`.

### Podman Notes

Podman users can substitute `docker` with `podman`. If you need host networking and serial devices:

```bash
[ -f ./.podman-auth_secret ] || openssl rand -base64 32 > ./.podman-auth_secret

podman run -d --name entrance-tools \
  --network host \
  --device /dev/ttyS0 \
  --device /dev/ttyS1 \
  -e AUTH_SECRET="$(tr -d '\n' < ./.podman-auth_secret)" \
  -e ENTRANCE_DATA_DIR=/data \
  -v entrance-tools-data:/data \
  entrance-tools:latest
```

> Replace `--device /dev/ttyS*` with the actual serial devices on your machine, such as `/dev/ttyUSB0` or `/dev/ttyACM0`. Host networking does not require `-p` port mapping.

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | HTTP listening port; can also be overridden with `npm start -- --port 4000` |
| `ENTRANCE_DATA_DIR` | repository root | Persistent data directory containing `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, and `.ssh_password_key` |
| `AUTH_SECRET` | none, required | Signing key for auth tokens; must be at least 32 bytes (base64 or 64 hex chars) |
| `SSH_PASSWORD_KEY` | auto-generates `.ssh_password_key` when unset | 32-byte key used to encrypt SSH/SFTP credentials and the private network allowlist; if set manually, it must remain stable across restarts |
| `AUTH_TOKEN_TTL` | `43200` | Auth token lifetime in seconds |
| `LOGIN_WINDOW_MS` | `900000` | Rate-limit window for failed logins in milliseconds |
| `LOGIN_MAX_ATTEMPTS` | `5` | Maximum failed logins allowed during the rate-limit window |
| `STRICT_HOST_KEY_CHECKING` | `false` | When `true`, reject unknown SSH host keys |
| `ALLOWED_TARGETS` | empty | Comma-separated allowlist of target hosts, supports `*.example.com` |
| `ALLOW_PRIVATE_NETWORKS` | `false` | When `true`, allow direct private-address access; otherwise admin allowlisting is required |
| `ENTRANCE_DESKTOP_NOLOGIN` | `0` | When `1`, skip login and access the app directly as `admin`; recommended only in trusted environments |

## Project Structure

```text
.
├── compose.yml          # Docker Compose configuration
├── Dockerfile           # Docker image build file
├── public/              # Frontend static assets
│   ├── index.html
│   └── vnc-client.js
├── server.js            # Backend server
├── local-shell.js       # Cross-platform local shell module
├── flash-debug.js       # Local flash/debug module (OpenOCD / pyOCD / probe-rs)
├── vnc.js               # VNC proxy module
├── nginx/               # Reverse proxy example config
├── package.json         # Dependency manifest
├── users.json           # User data (generated, may live under ENTRANCE_DATA_DIR)
├── .ssh_password_key    # SSH credential encryption key (generated)
├── known_hosts.json     # SSH host fingerprints (generated)
├── private-networks.json  # Private network allowlist (generated, encrypted)
└── userdata/            # User data directory (generated)
    ├── admin.json       # Saved hosts for admin
    └── user1.json       # Saved hosts for user1
```

## Technology Stack

### Frontend
- Plain HTML/CSS/JavaScript
- Single-file frontend with built-in theme, color scheme, and UI language switching logic
- [xterm.js](https://xtermjs.org/) - terminal emulator
- [Chart.js](https://www.chartjs.org/) - waveform/stat visualization
- [noVNC](https://novnc.com/) - VNC client
- [Font Awesome](https://fontawesome.com/) - icon set

### Backend
- [Express](https://expressjs.com/) - web framework
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH client
- script + child_process / localhost SSH - local terminal support (Linux/macOS/Windows, no native compilation)
- OpenOCD / pyOCD / probe-rs - local flashing and debugging toolchain
- [argon2](https://github.com/ranisalt/node-argon2) - Argon2id password hashing
- [multer](https://github.com/expressjs/multer) - file uploads
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP packaging

> **Note**: Local Shell supports Linux, macOS, and Windows. Linux/macOS uses `script` to create PTYs. Windows no longer spawns `COMSPEC`/PowerShell directly; instead it connects to local `OpenSSH Server` on `127.0.0.1` to get correct terminal editing semantics.

## API

### Authentication
- `POST /api/auth/login` - sign in and return a token
- `POST /api/auth/verify` - verify a token

All APIs require `Authorization: Bearer <token>` in the request header.

### User Data
- `GET /api/userdata/:userId/hosts` - get saved hosts
- `POST /api/userdata/:userId/hosts` - add a host
- `DELETE /api/userdata/:userId/hosts/:index` - delete a host

### SFTP
- `POST /api/sftp/connect` - open a connection
- `POST /api/sftp/disconnect/:sessionId` - close a connection
- `GET /api/sftp/list/:sessionId` - list a directory
- `GET /api/sftp/home/:sessionId` - get the home directory
- `POST /api/sftp/mkdir/:sessionId` - create a directory
- `DELETE /api/sftp/delete/:sessionId` - delete a file or directory
- `POST /api/sftp/upload/:sessionId` - upload files
- `GET /api/sftp/download/:sessionId` - download a file
- `POST /api/sftp/download-zip/:sessionId` - download a ZIP bundle

Example SFTP connection payloads:

```javascript
// Password auth
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "password",
  "password": "xxx"
}

// Private key auth
{
  "host": "192.168.1.10",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}
```

### Security Configuration
- `GET /api/security/private-networks` - get the private CIDR allowlist (admin)
- `PUT /api/security/private-networks` - update the private CIDR allowlist (admin)

### SSH (WebSocket)

Connect to `ws://host:port/ssh?token=...` with messages like:

```javascript
// Connect
{ "type": "connect", "host": "192.168.1.1", "port": 22, "username": "root", "password": "xxx" }

// Connect with private key
{
  "type": "connect",
  "host": "192.168.1.1",
  "port": 22,
  "username": "root",
  "authType": "key",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "passphrase": "optional"
}

// Send data
{ "type": "data", "data": "ls -la\n" }

// Resize terminal
{ "type": "resize", "cols": 80, "rows": 24 }

// Disconnect
{ "type": "disconnect" }

// Start system stats (sample /proc/stat, /proc/meminfo, /proc/diskstats every second)
{ "type": "startStats" }

// Stop system stats
{ "type": "stopStats" }

// Start process stats (sample uptime and ps aux every 2 seconds)
{ "type": "startTop" }

// Stop process stats
{ "type": "stopTop" }

// Refresh process list manually
{ "type": "refreshTop" }

// Send a signal to a process
{ "type": "kill", "pid": 1234, "signal": 15 }

// Start Docker stats (sample docker stats --no-stream every 3 seconds)
{ "type": "startDockerStats" }

// Stop Docker stats
{ "type": "stopDockerStats" }

// Refresh Docker stats manually
{ "type": "refreshDockerStats" }
```

System stats payload returned by the server:

```javascript
{
  "type": "stats",
  "data": {
    "stat": "cpu  12345 678 ...",      // /proc/stat output
    "meminfo": "MemTotal: ...",         // /proc/meminfo output
    "diskstats": "8 0 sda ..."          // /proc/diskstats output
  }
}
```

Process stats payload returned by the server:

```javascript
{
  "type": "top",
  "data": {
    "uptime": "10:15:03 up 5 days...",  // uptime output
    "ps": "USER PID %CPU %MEM ..."       // ps aux output
  }
}
```

Docker stats payload returned by the server:

```javascript
{
  "type": "dockerStats",
  "data": {
    "available": true,                // whether Docker is available
    "error": null,                    // error message when unavailable
    "containers": [                   // container list from docker stats --format json
      {
        "ID": "abc123...",
        "Name": "my-container",
        "CPUPerc": "1.25%",
        "MemPerc": "12.50%",
        "MemUsage": "256MiB / 2GiB",
        "NetIO": "1.2MB / 3.4MB",
        "BlockIO": "10MB / 20MB",
        "PIDs": "15"
      }
    ]
  }
}
```

Kill-process result returned by the server:

```javascript
{
  "type": "killResult",
  "data": {
    "success": true,
    "message": "SIGTERM sent to PID 1234"
  }
}
```

### VNC (WebSocket)

Connect to `ws://host:port/vnc`; the server proxies traffic to the target VNC server.

Message format:

```javascript
// Initial target info
{ "type": "connect", "host": "192.168.1.1", "port": 5900 }
```

### Local Shell (WebSocket)

Linux/macOS uses `ws://host:port/localshell` for the server-local terminal. On Windows, the Web Terminal page switches internally to `ws://host:port/ssh` and connects to `127.0.0.1`.

Message format:

```javascript
// Start shell
{ "type": "start", "cols": 80, "rows": 24, "cwd": "/home/user" }

// Send input
{ "type": "data", "data": "ls -la\n" }

// Resize
{ "type": "resize", "cols": 120, "rows": 40 }

// Stop shell
{ "type": "stop" }
```

Status API:
- `GET /api/localshell/status` - get local shell service status

### Flash & Debug

- `GET /api/flashdebug/tooling?tool=openocd|pyocd|probe-rs[&path=/abs/path]` - detect executable paths, probe lists, OpenOCD config catalogs, and available elevation methods on the current platform
- `POST /api/flashdebug/upload` - upload firmware files to a temporary directory on the current Entrance host

Connect to `ws://host:port/flashdebug?token=...` with messages like:

```javascript
// Start flashing
{
  "type": "start",
  "action": "flash",
  "tool": "openocd",
  "requestElevation": true,
  "executablePath": "",
  "options": {
    "probeSelection": "cmsis-dap",
    "targetConfig": "target/stm32f4x.cfg",
    "interfaceConfig": "",
    "speed": "4000",
    "firmwarePath": "/tmp/app.bin",
    "verify": true,
    "resetAfterFlash": true,
    "extraArgs": ""
  }
}

// Start live debugging
{
  "type": "start",
  "action": "debug",
  "tool": "pyocd",
  "requestElevation": false,
  "options": {
    "probeSelection": "",
    "target": "stm32f103rc",
    "speed": "1000000",
    "gdbPort": 3333,
    "telnetPort": 4444,
    "elfPath": "/tmp/app.elf",
    "extraArgs": ""
  }
}

// Stop current task
{ "type": "stop" }
```

The server returns:
- `started` - task started, includes the final command preview
- `output` - stdout/stderr/system output stream
- `exit` - process exit status
- `error` - startup failure or runtime error

### Serial Data Formats (WebSerial)

The serial terminal automatically parses two mutually exclusive formats without interference:

#### Waveform Data Format

Used for real-time waveform rendering in the format `VariableName:NumericValue`:

```
ADC1:1024
Temp:25.5
Sin:-0.866
Voltage:3.3
```

Single-line multi-variable input is also supported:

```
a:2, b:4, temp:25.5
```

- Variable name: starts with a letter or underscore; may contain letters, numbers, and underscores
- Value: integer or float, supports negatives
- One or more data points per line, separated by newlines
- Each variable gets a distinct color automatically

#### Stat Chart Data Format

Used for bar-chart comparisons in the format `varName:[key1:value1, key2:value2, ...]`:

```
stats:[a:2, b:3, c:5, d:6]
```

Single-line multiple variables are also supported:

```
var1:[a:4, b:6], var2:[a:6, b:3, c:2]
```

Multi-line parsing is supported as well:

```
cpu:[user:45, system:12, idle:43]
memory:[used:8192, free:4096, cached:2048]
```

- Variable name such as `stats` or `var1`: used as the X-axis label
- Subkeys such as `a`, `b`, `c`: each subkey uses a distinct color
- Value: integer or float, supports negatives
- Matching subkey names reuse the same color across variables for easier comparison

## Security Notes

- Login is enabled by default. Auth tokens are signed with `AUTH_SECRET`; login is skipped only when `ENTRANCE_DESKTOP_NOLOGIN=1`.
- Passwords in `users.json` are stored as `Argon2id` hashes. Legacy plaintext passwords are migrated automatically after a successful login.
- SSH/SFTP credentials, including passwords, private keys, and passphrases, are stored only in the browser or in server-side user data; when persisted, they are encrypted with AES-256-GCM using `SSH_PASSWORD_KEY`.
- The private network allowlist is stored in `private-networks.json` and encrypted with AES-256-GCM using `SSH_PASSWORD_KEY`.
- If `SSH_PASSWORD_KEY` changes, historical encrypted credentials and allowlist entries become unreadable until the old key is restored or the data is re-entered.
- **Local Shell Security** (Linux/macOS/Windows, admin only): local shell access gives direct terminal access to the server. Make sure to:
  - use it only on trusted networks
  - restrict access to authorized administrators
  - on Windows, enable only the local `OpenSSH Server` and limit which local accounts may log in
  - consider disabling this feature in production or adding extra authentication at the reverse proxy layer
- **Flash/Debug Security** (admin only): flashing/debugging can invoke local toolchains directly and optionally request admin/root privileges. Make sure to:
  - enable it only on trusted developer machines or lab environments
  - keep executables such as `OpenOCD`, `pyOCD`, `probe-rs`, `pkexec`, `sudo`, and `gsudo` within a trusted supply chain
  - enable "request admin/root privileges" only when device access or driver permissions actually require it
  - when using Linux GUI password dialog mode, ensure `zenity` or `kdialog` comes from the system package manager

## License

GPL-3.0 License

## Contributing

Issues and pull requests are welcome.

## Acknowledgements

Thanks to everyone who tested Entrance on real machines across browsers, operating systems, serial devices, remote hosts, and flashing/debugging workflows. Your feedback helped catch regressions and improve both the product experience and the bilingual documentation.
