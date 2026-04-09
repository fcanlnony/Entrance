# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Entrance Tools is a web-based server management tool that supports SSH terminals, VNC remote desktops, WebSerial terminals, local flashing/debugging workflows, SFTP file management, and Docker container monitoring.

Documentation is English-first: keep the root `README.md` as the default English README, keep the Simplified Chinese translation in `doc/README_CN.md`, use `doc/screenshot.png` from the root README, and use `screenshot_cn.png` inside `doc/README_CN.md`. Keep `AGENTS.md` and `CLAUDE.md` in English when updating repository guidance. Preserve each document's existing language when editing it; do not mix languages inside a file unless that file already does so intentionally. When `README.md` changes, update every corresponding `README_XX.md` translation document in the repository in the same pass; in this repository that means `doc/README_CN.md` must stay aligned with `README.md`.

## Build and Development Commands

```bash
# Install dependencies
npm install

# Rebuild generated frontend assets from webui-src/
npm run build:webui

# Start the development server
npm start
# or
npm run dev
# or
node server.js
# or on a custom port
PORT=4000 npm start
# or
npm start -- --port 4000

# Default server URL: http://localhost:3000

# Container workflows
docker build -t entrance-tools .
docker compose up -d --build
# or
PORT=4000 docker compose up -d --build
# Podman users can substitute docker with podman
```

## Environment Variables

- `AUTH_SECRET` (required) - Auth token signing key; must decode to at least 32 bytes.
- `SSH_PASSWORD_KEY` (optional) - 32-byte AES key for stored SSH credentials and private-network allowlists; if omitted, the server writes a generated key to `.ssh_password_key` under `ENTRANCE_DATA_DIR`.
- `PORT` - HTTP port, defaults to `3000`; can also be overridden by the `--port` / `-p` startup flag.
- `ENTRANCE_HOST` - Explicit bind host override. Defaults to `0.0.0.0` in web mode and `127.0.0.1` in desktop API-only mode.
- `ENTRANCE_DATA_DIR` - Runtime data directory for `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, `LOGIN_KEEP`, and `.ssh_password_key`. Do not upload or commit this directory, `.data/`, or any other user/runtime data directories.
- `AUTH_TOKEN_TTL` - Default password-login token lifetime in seconds, defaults to `604800` and can be overridden from the in-app Settings keepalive control.
- `LOGIN_WINDOW_MS` / `LOGIN_MAX_ATTEMPTS` - Login rate-limit window and failure threshold.
- `STRICT_HOST_KEY_CHECKING` - When `true`, reject unknown SSH host keys instead of learning them.
- `ALLOWED_TARGETS` - Comma-separated allowlist for SSH/VNC target hosts; supports exact names and `*.example.com` patterns.
- `ALLOW_PRIVATE_NETWORKS` - When `true`, skip the admin-managed private CIDR whitelist check.
- `ENTRANCE_DESKTOP_NOLOGIN` - When set to `1`, enable desktop no-login mode. Use it with the API-only bootstrap flow for secure Electron deployments.
- `ENTRANCE_DESKTOP_API_ONLY` - When set to `1`, disable static WebUI serving and expose backend APIs only.
- `ENTRANCE_DESKTOP_ALLOWED_ORIGIN` - Allowed renderer origin for desktop API-only CORS, defaults to `app://entrance`.
- `ENTRANCE_DESKTOP_BOOTSTRAP_SECRET` - Required when both `ENTRANCE_DESKTOP_API_ONLY=1` and `ENTRANCE_DESKTOP_NOLOGIN=1`; used by the desktop wrapper to obtain the admin no-login token securely.

## Architecture Overview

### Project Structure
```
.
├── .dockerignore       # Container build exclusions
├── compose.yml         # Docker Compose service definition
├── Dockerfile          # Container image build
├── public/
│   ├── assets/         # Generated frontend CSS/JS assets
│   ├── index.html      # Generated frontend entrypoint
│   ├── logo.png        # Startup splash logo shown inside the rounded loading card
│   └── vnc-client.js   # VNC browser client
├── webui-src/
│   ├── index.template.html  # Frontend template entrypoint
│   ├── partials/            # HTML fragments for each view/modal/layout section
│   ├── scripts/app.js       # Frontend application logic source
│   └── styles/app.css       # Frontend stylesheet source
├── scripts/build-webui.js  # Regenerates public/index.html and public/assets/*
├── server.js           # Express backend server (HTTP + WebSocket + auth + SSH/SFTP/Docker)
├── local-shell.js      # Local shell module (Linux/macOS via script, Windows via direct shell spawn)
├── flash-debug.js      # Admin-only local flash/debug module (OpenOCD / pyOCD / probe-rs + optional elevation)
├── vnc.js              # VNC WebSocket proxy
├── package.json        # Dependency manifest
├── users.json          # User account data (generated at runtime, Argon2 hashes)
├── LOGIN_KEEP          # Encrypted password-login timestamp used for session keepalive
├── known_hosts.json    # SSH host key cache (generated at runtime)
├── private-networks.json  # Encrypted private CIDR allowlist (generated at runtime)
├── .ssh_password_key   # Generated AES key when SSH_PASSWORD_KEY is not supplied
└── userdata/           # User data directory (generated at runtime; encrypted SSH secrets live here)
```

### Frontend Architecture
- Editable frontend source lives in `webui-src/`; generated output lives in `public/`
- `scripts/build-webui.js` resolves `{{> ...}}` partial includes and copies `webui-src/styles/app.css` and `webui-src/scripts/app.js` into `public/assets/`
- Modular JavaScript objects: `State`, `Storage`, `Theme`, `Settings`, `I18n`, `Toast`, `Terminal_`, `FlashDebug`, `SFTP`, `Hosts`, `UI`
- CSS variables for theme switching and Material You color scheme support (`data-color-scheme` attribute)
- UI i18n support with English as the default language and Simplified Chinese as the secondary option
- Microsoft Fluent Design style
- Startup/auth overlay behavior:
  - When a saved login is being restored and `ENTRANCE_DESKTOP_NOLOGIN` is not enabled, show a Material You wave splash with `public/logo.png` clipped into a rounded rectangle
  - Keep a minimum 3-second progress animation even if backend verification is fast
  - Render the dashboard shell first, then initialize backend-backed modules in stages
  - The splash markup lives in `webui-src/partials/auth-overlay.html`, the styling lives in `webui-src/styles/app.css`, and the runtime loading/boot sequence lives in `webui-src/scripts/app.js` (`showLoading`, `updateLoadingProgress`, `startDashboardBoot`)
  - In secure desktop no-login mode, the Electron wrapper should own the bootstrap, call `POST /api/auth/desktop/bootstrap`, and inject auth into API/WebSocket requests without exposing the token to the renderer
- `FlashDebug` now uses a shared autocomplete pipeline for tool-specific target inputs:
  - OpenOCD target configs and interface configs
  - pyOCD target names from `pyocd list --targets --no-header`
  - probe-rs chip names from `probe-rs chip list`
  - Flash & Debug placeholders, helper hints, candidate counters, and fallback probe/catalog notices also run through the shared path and should follow the active UI language

### Backend Architecture
- Express.js HTTP/REST API server
- WebSocket upgrade handling for SSH, VNC, admin-only local shell sessions, and admin-only flash/debug sessions
- ssh2 library for SSH/SFTP functionality
- Auth/token system in `server.js` (signed bearer tokens, login throttling, encrypted `LOGIN_KEEP`, `AUTH_SECRET` fingerprint checks, browser login flows, and desktop API-only bootstrap mode)
- Private target validation via allowlists, private-network CIDR management, and known-host verification
- File storage for user data, known hosts, and encrypted secrets
- `flash-debug.js` wraps OpenOCD, pyOCD, and probe-rs, including optional OS-level privilege elevation requests
- Container deployment support via `Dockerfile` and `compose.yml`

### Core Modules
1. **UserManager** - User account management, Argon2 hashing, and legacy plaintext migration
2. **UserDataManager** - Per-user host storage and encrypted SSH credential persistence
3. **Auth / Token System** - Login verification, rate limiting, signed bearer tokens, `AUTH_SECRET` fingerprint-aware session reuse, encrypted `LOGIN_KEEP`, and optional desktop no-login mode
4. **PrivateNetworkManager** - Admin-managed private CIDR allowlist stored encrypted at rest
5. **Known Hosts Cache** - SSH host key pinning and strict host key checking support
6. **SFTP Sessions** - In-memory SFTP session management
7. **Local Shell Service** - Cross-platform local shell WebSocket endpoint
8. **Flash Debug Service** - Admin-only local flashing/debugging WebSocket + REST endpoints, tool discovery, uploads, and privilege-elevation wrapping
   - Includes shared target autocomplete catalogs for OpenOCD / pyOCD / probe-rs
9. **Docker Stats** - Docker container resource monitoring via `docker stats --no-stream`
10. **Settings** - In-app settings view for password change (disabled in `ENTRANCE_DESKTOP_NOLOGIN` mode), login keepalive presets/custom duration input, an admin-only private-network allowlist card below the keepalive/password cards, Material You color scheme selection (default, sakura, ocean, forest, twilight, amber), and a separate language selector card below the color scheme card (default English; supports Chinese/English)

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
2. Frontend features: change `webui-src/scripts/app.js`, `webui-src/styles/app.css`, or the relevant `webui-src/partials/*.html` file, then regenerate `public/` with `npm run build:webui`
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
- Password-login keepalive defaults to 7 days. The browser stores the chosen duration and only keeps restoring the saved session while token verification succeeds and the current `AUTH_SECRET` fingerprint still matches.
- `LOGIN_KEEP` stores the last successful password-login Unix timestamp encrypted with AES-256-GCM using a key derived from `AUTH_SECRET`.
- Stored SSH credentials and private-network allowlist entries are AES-256-GCM encrypted with `SSH_PASSWORD_KEY`.
- If `SSH_PASSWORD_KEY` changes, existing encrypted secrets become unreadable until the old key is restored or the values are re-entered.
- Desktop no-login should not expose `/api/auth/nologin` to browsers. Use `ENTRANCE_DESKTOP_API_ONLY=1`, loopback binding, and the `POST /api/auth/desktop/bootstrap` + `X-Entrance-Desktop-Secret` flow instead.
- SFTP sessions are stored in memory (Map).
- User data is isolated per user in separate JSON files under `ENTRANCE_DATA_DIR`.
- Never upload or commit `.data/`, `ENTRANCE_DATA_DIR` contents, `userdata/`, generated runtime JSON, or any other user data snapshots.
- Local shell access is admin-only and supported on Linux, macOS, and Windows.
- Flash/debug access is admin-only. The UI can optionally request elevated privileges before launching OpenOCD/pyOCD/probe-rs:
  - Linux: `pkexec`, or `sudo` with `zenity` / `kdialog` askpass
  - macOS: `sudo` with `osascript`
  - Windows: `gsudo` or `sudo`
- Flash/debug target fields use shared local-search autocomplete. OpenOCD searches discovered config catalogs, pyOCD searches the target catalog returned by `pyocd list --targets --no-header`, and probe-rs searches the chip catalog returned by `probe-rs chip list`.
- Flash/debug helper copy is part of the same shared frontend path. When changing placeholders, helper hints, or fallback enumeration/catalog messages, keep Chinese and English behavior aligned across OpenOCD, pyOCD, and probe-rs.
- The Settings view allows users to change their own password via `PUT /api/users/:username/password` (Argon2id hashed), adjust login keepalive via presets or a custom duration string, and, for admins, manage the private-network allowlist in a separate card. When `ENTRANCE_DESKTOP_NOLOGIN=1`, the password/login-restore UI stays disabled and the desktop wrapper is expected to provide the loading animation instead.
- Color schemes are stored in `localStorage` (`colorScheme` key) and applied via the `data-color-scheme` attribute on `<html>`. Available schemes: default, sakura, ocean, forest, twilight, amber.
- UI language is stored in `localStorage` (`language` key). The app defaults to English and currently supports Simplified Chinese and English.
