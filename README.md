# Entrance Tools

Default documentation is in English. For Simplified Chinese, see [doc/README_CN.md](doc/README_CN.md).

Web-based server management tools with SSH terminal access, local shell terminal access, VNC remote desktop, WebSerial terminal support, flashing/debugging workflows, and SFTP file management. The UI follows Microsoft Fluent Design, supports light/dark themes, and includes both Chinese and English interface modes.
![Screenshot](doc/screenshot.png)

For the installer script, see [Install](https://github.com/EntranceToolBox/Entrance-Installer).

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

### Plugin System
- Sidebar entries for **Plugin Install** and **Plugin Navigator** above Settings
- Administrators can install ZIP plugin packages and delete installed plugins from the Fluent Design card UI
- Plugin cards show plugin name, version, author, description, entry file, and project homepage
- Plugin Navigator opens an installed plugin inside the workspace, similar to built-in pages such as Serial Terminal
- Installed plugins are stored under `.plugins/` in `ENTRANCE_DATA_DIR` (repo-root `.plugins/` by default)
- The root `api/` directory contains the plugin package contract examples: `version.json`, `index.js`, and `index.html`

### UI Features
- Microsoft Fluent Design
- Light / dark theme toggle
- **Staged Startup Splash**
  - When a saved login is restored and `ENTRANCE_DESKTOP_NOLOGIN` is not enabled, the app shows a Material You style wave splash with the rounded `logo.png` card
  - The splash keeps a minimum 3-second progress animation even when boot is fast
  - The dashboard shell renders first, then terminal/serial/VNC/local-shell/security modules initialize in stages
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
- **Session Keepalive** - default password-login keepalive is 7 days; users can change it from Settings with presets (`7d`, `14d`, `1m`, `never`) or custom expressions
- Saved sessions remain reusable across restarts as long as `AUTH_SECRET` stays unchanged; changing `AUTH_SECRET` forces a fresh sign-in
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

# Start the service with persistent local runtime data under ./.data
./start.sh
# or use permissive CORS for LAN / reverse-proxy / tunnel browser access
./start_nocors.sh
```

`./start.sh` is the preferred local entry point. On the first run, when `./.data` does not exist yet, it creates `./.data`, writes `./.data/auth_secret`, exports `ENTRANCE_DATA_DIR` and `AUTH_SECRET`, and then runs `npm start`. It also accepts `--port=4000`, which makes it call `npm start -- --port 4000`.

`./start_nocors.sh` is the same bootstrap flow with `ENTRANCE_CORS_DISABLE=1` exported first. Use it only when you intentionally need browser access from a LAN IP, reverse proxy, or tunnel domain.

`npm start` still rebuilds the modular WebUI from `webui-src/` before launching the server, but it requires `AUTH_SECRET` to already be exported. Use `npm run build:webui` if you only want to refresh the generated frontend assets.

Visit http://localhost:3000 and sign in to enter the dashboard.

Run the plugin smoke test when touching plugin install, navigation, or package contract behavior:

```bash
npm run test:plugins
```

To use a different port, use an environment variable or CLI flag:

```bash
./start.sh --port=4000
# or
./start_nocors.sh --port=4000
# or, if AUTH_SECRET is already exported
PORT=4000 npm start
# or
npm start -- --port 4000
```

Then open `http://localhost:4000`.

### Manual Equivalent of `start.sh`

```bash
if [ ! -d ./.data ]; then
  mkdir -p ./.data
  [ -f ./.data/auth_secret ] || openssl rand -base64 32 > ./.data/auth_secret
fi

export ENTRANCE_DATA_DIR="$(pwd)/.data"
export AUTH_SECRET="$(tr -d '\n' < ./.data/auth_secret)"
npm start
```

This matches `./start.sh` without a custom port. If you run `./start.sh --port=4000`, the final line becomes `npm start -- --port 4000`. If `./.data` already exists, the script does not regenerate `./.data/auth_secret`, so make sure that file is still present before restarting. The runtime data stays pinned to `./.data`, and Entrance generates and reuses the SSH credential encryption key in `./.data/.ssh_password_key`. Do not regenerate `SSH_PASSWORD_KEY` before each restart, or existing allowlists, passwords, and private keys will become undecryptable.

The default account is `admin/admin` on first boot.

### Container Deployment

For Docker, Docker Compose, and Podman deployment, see [doc/container.md](doc/container.md).

## Environment Variables

For behavior-focused notes, defaults, side effects, and deployment guidance, see [doc/environment-variables.md](doc/environment-variables.md).

## Project Structure

```text
.
├── compose.yml          # Docker Compose configuration
├── Dockerfile           # Docker image build file
├── public/              # Frontend static assets
│   ├── assets/          # Generated CSS/JS bundles built from webui-src/
│   ├── index.html       # Generated frontend entrypoint
│   └── vnc-client.js
├── api/                 # Plugin package contract examples
├── webui-src/           # Editable WebUI source files and HTML partials
│   ├── index.template.html
│   ├── partials/
│   ├── scripts/app.js
│   └── styles/app.css
├── server.js            # Backend server
├── local-shell.js       # Cross-platform local shell module
├── flash-debug.js       # Local flash/debug module (OpenOCD / pyOCD / probe-rs)
├── vnc.js               # VNC proxy module
├── nginx/               # Reverse proxy example config
├── package.json         # Dependency manifest
├── start.sh             # Local startup helper that exports ENTRANCE_DATA_DIR and AUTH_SECRET from ./.data and accepts --port=4000
├── start_nocors.sh      # Wrapper around start.sh that exports ENTRANCE_CORS_DISABLE=1 first
├── users.json           # User data (generated, may live under ENTRANCE_DATA_DIR)
├── .ssh_password_key    # SSH credential encryption key (generated)
├── .plugins/            # Installed plugins (generated under ENTRANCE_DATA_DIR)
├── LOGIN_KEEP           # Encrypted password-login timestamp for session keepalive
├── known_hosts.json     # SSH host fingerprints (generated)
├── private-networks.json  # Private network allowlist (generated, encrypted)
└── userdata/            # User data directory (generated)
    ├── admin.json       # Saved hosts for admin
    └── user1.json       # Saved hosts for user1
```

WebUI source is split by responsibility:

- `webui-src/partials/auth-overlay.html` contains the login overlay plus the staged loading/splash markup.
- `webui-src/styles/app.css` contains the auth overlay and startup animation styles.
- `webui-src/scripts/app.js` contains the auth/loading controller (`showLoading`, `updateLoadingProgress`) and the staged dashboard boot sequence (`startDashboardBoot`).
- `public/index.html` and `public/assets/*` are generated outputs from those source files.

## Technology Stack

See [doc/TechnologyStack.md](doc/TechnologyStack.md).

## API

See [doc/api.md](doc/api.md).

## Security Notes

See [doc/security_note.md](doc/security_note.md).

### Friend Links

- EK-OmniProbe https://github.com/EmbeddedKitOrg/EK-OmniProbe
- Clion-Waveform-Plotter https://github.com/Szturin/Clion-Waveform-Plotter

## License

GPL-3.0 License

## Contributing

Issues and pull requests are welcome.
