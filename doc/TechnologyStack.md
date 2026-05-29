# Technology Stack

## Frontend

- Plain HTML/CSS/JavaScript
- Single-file frontend with built-in theme, color scheme, and UI language switching logic
- [xterm.js](https://xtermjs.org/) - terminal emulator
- [Chart.js](https://www.chartjs.org/) - waveform/stat visualization
- [noVNC](https://novnc.com/) - VNC client
- [Font Awesome](https://fontawesome.com/) - icon set

## Backend

- [Express](https://expressjs.com/) - web framework
- [ws](https://github.com/websockets/ws) - WebSocket
- [ssh2](https://github.com/mscdex/ssh2) - SSH client
- script + child_process / localhost SSH - local terminal support (Linux/macOS/Windows, no native compilation)
- OpenOCD / pyOCD / probe-rs - local flashing and debugging toolchain
- [argon2](https://github.com/ranisalt/node-argon2) - Argon2id password hashing
- [multer](https://github.com/expressjs/multer) - file uploads
- [archiver](https://github.com/archiverjs/node-archiver) - ZIP packaging
- [adm-zip](https://github.com/cthackers/adm-zip) - plugin ZIP extraction

> **Note**: Local Shell supports Linux, macOS, and Windows. Linux/macOS uses `script` to create PTYs. Windows no longer spawns `COMSPEC`/PowerShell directly; instead it connects to local `OpenSSH Server` on `127.0.0.1` to get correct terminal editing semantics.
