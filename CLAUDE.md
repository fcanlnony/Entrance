# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Entrance Tools is a web-based server management tool that supports SSH terminals, VNC remote desktops, WebSerial terminals, local flashing/debugging workflows, SFTP file management, and Docker container monitoring.

## Build and Development Commands

```bash
# Install dependencies
npm install

# Start the development server
npm start
# or
npm run dev
# or
node server.js

# Default server URL: http://localhost:3000

# Container workflows
docker build -t entrance-tools .
docker compose up -d --build
# Podman users can substitute docker with podman
```

## Environment Variables

- `AUTH_SECRET` (required) - Auth token signing key; must decode to at least 32 bytes.
- `SSH_PASSWORD_KEY` (optional) - 32-byte AES key for stored SSH credentials and private-network allowlists; if omitted, the server writes a generated key to `.ssh_password_key` under `ENTRANCE_DATA_DIR`.
- `PORT` - HTTP port, defaults to `3000`.
- `ENTRANCE_DATA_DIR` - Runtime data directory for `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, and `.ssh_password_key`.
- `AUTH_TOKEN_TTL` - Bearer token lifetime in seconds, defaults to `43200`.
- `LOGIN_WINDOW_MS` / `LOGIN_MAX_ATTEMPTS` - Login rate-limit window and failure threshold.
- `STRICT_HOST_KEY_CHECKING` - When `true`, reject unknown SSH host keys instead of learning them.
- `ALLOWED_TARGETS` - Comma-separated allowlist for SSH/VNC target hosts; supports exact names and `*.example.com` patterns.
- `ALLOW_PRIVATE_NETWORKS` - When `true`, skip the admin-managed private CIDR whitelist check.
- `ENTRANCE_DESKTOP_NOLOGIN` - When set to `1`, bypass login and auto-authenticate as `admin`.

## Architecture Overview

### Project Structure
```
.
├── .dockerignore       # Container build exclusions
├── compose.yml         # Docker Compose service definition
├── Dockerfile          # Container image build
├── public/
│   ├── index.html      # Single-page frontend (HTML + CSS + JavaScript)
│   └── vnc-client.js   # VNC browser client
├── server.js           # Express backend server (HTTP + WebSocket + auth + SSH/SFTP/Docker)
├── local-shell.js      # Local shell module (Linux/macOS via script, Windows via direct shell spawn)
├── flash-debug.js      # Admin-only local flash/debug module (OpenOCD / pyOCD / probe-rs + optional elevation)
├── vnc.js              # VNC WebSocket proxy
├── package.json        # Dependency manifest
├── users.json          # User account data (generated at runtime, Argon2 hashes)
├── known_hosts.json    # SSH host key cache (generated at runtime)
├── private-networks.json  # Encrypted private CIDR allowlist (generated at runtime)
├── .ssh_password_key   # Generated AES key when SSH_PASSWORD_KEY is not supplied
└── userdata/           # User data directory (generated at runtime; encrypted SSH secrets live here)
```

### Frontend Architecture
- Single-file HTML app with no build step
- Modular JavaScript objects: `State`, `Storage`, `Theme`, `Settings`, `Toast`, `Users`, `Terminal_`, `FlashDebug`, `SFTP`, `Hosts`, `UI`
- CSS variables for theme switching and Material You color scheme support (`data-color-scheme` attribute)
- Microsoft Fluent Design style

### Backend Architecture
- Express.js HTTP/REST API server
- WebSocket upgrade handling for SSH, VNC, admin-only local shell sessions, and admin-only flash/debug sessions
- ssh2 library for SSH/SFTP functionality
- Auth/token system in `server.js` (signed bearer tokens, login throttling, optional no-login mode)
- Private target validation via allowlists, private-network CIDR management, and known-host verification
- File storage for user data, known hosts, and encrypted secrets
- `flash-debug.js` wraps OpenOCD, pyOCD, and probe-rs, including optional OS-level privilege elevation requests
- Container deployment support via `Dockerfile` and `compose.yml`

### Core Modules
1. **UserManager** - User account management, Argon2 hashing, and legacy plaintext migration
2. **UserDataManager** - Per-user host storage and encrypted SSH credential persistence
3. **Auth / Token System** - Login verification, rate limiting, signed bearer tokens, and optional desktop no-login mode
4. **PrivateNetworkManager** - Admin-managed private CIDR allowlist stored encrypted at rest
5. **Known Hosts Cache** - SSH host key pinning and strict host key checking support
6. **SFTP Sessions** - In-memory SFTP session management
7. **Local Shell Service** - Cross-platform local shell WebSocket endpoint
8. **Flash Debug Service** - Admin-only local flashing/debugging WebSocket + REST endpoints, tool discovery, uploads, and privilege-elevation wrapping
9. **Docker Stats** - Docker container resource monitoring via `docker stats --no-stream`
10. **Settings** - In-app settings view for password change (disabled in `ENTRANCE_DESKTOP_NOLOGIN` mode) and Material You color scheme selection (default, sakura, ocean, forest, twilight, amber)

### SSH Monitoring Panels
The SSH view includes three collapsible monitoring panels below the terminal:
1. **System Stats** - Real-time CPU/Memory/Disk I/O line chart (1s interval via `/proc/*`)
2. **TOP (Process List)** - Process table with sort/filter/kill (2s interval via `ps aux`)
3. **Docker Stats** - Container resource rings for CPU/MEM/NET IO/BLOCK IO (3s interval via `docker stats --no-stream`), with "Total" (aggregate) and "Single" (per-container) view modes

All three panels follow the same pattern: `collectXxx()` server function → `setInterval` polling → WebSocket message → client `handleXxx()` → render.

## Key Dependencies

### Backend
- `express` - Web framework
- `ws` - WebSocket server
- `ssh2` - SSH/SFTP client
- `argon2` - Password hashing and legacy password migration
- `multer` - File upload middleware
- `archiver` - ZIP packaging

### Frontend (CDN)
- `xterm.js` - Terminal emulator
- `xterm-addon-fit` - Terminal fit addon
- `Chart.js` - System stats line chart
- `noVNC` - VNC client
- `Font Awesome` - Icon library

## Development Workflow

### Adding Features
1. Backend API: add routes in `server.js`
2. Frontend features: add logic in the relevant module inside `index.html`
3. Testing: run `npm start` and test locally

### Code Style
- Use ES6+ syntax
- Use async/await for asynchronous work
- Error handling: backend returns JSON `{ error: "message" }`, frontend shows Toast notifications

### API Naming Conventions
- RESTful style
- Paths: `/api/{resource}/{action}`
- Auth: `/api/auth/*`
- User management: `/api/users/*`
- User data: `/api/userdata/:userId/*`
- SFTP actions: `/api/sftp/*`

## Important Notes

- Default account: `admin / admin` on first boot.
- Password storage: Argon2id hashes in `users.json`; legacy plaintext entries are upgraded on successful login.
- Stored SSH credentials and private-network allowlist entries are AES-256-GCM encrypted with `SSH_PASSWORD_KEY`.
- If `SSH_PASSWORD_KEY` changes, existing encrypted secrets become unreadable until the old key is restored or the values are re-entered.
- SFTP sessions are stored in memory (Map).
- User data is isolated per user in separate JSON files under `ENTRANCE_DATA_DIR`.
- Local shell access is admin-only and supported on Linux, macOS, and Windows.
- Flash/debug access is admin-only. The UI can optionally request elevated privileges before launching OpenOCD/pyOCD/probe-rs:
  - Linux: `pkexec`, or `sudo` with `zenity` / `kdialog` askpass
  - macOS: `sudo` with `osascript`
  - Windows: `gsudo` or `sudo`
- The Settings view allows users to change their own password via `PUT /api/users/:username/password` (Argon2id hashed). When `ENTRANCE_DESKTOP_NOLOGIN=1`, the password form is hidden and a notice is shown instead.
- Color schemes are stored in `localStorage` (`colorScheme` key) and applied via the `data-color-scheme` attribute on `<html>`. Available schemes: default, sakura, ocean, forest, twilight, amber.
