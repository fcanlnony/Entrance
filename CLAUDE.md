# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Entrance Tools is a web-based server management tool that supports SSH terminals, VNC remote desktops, WebSerial terminals, SFTP file management, and Docker container monitoring.

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
```

## Architecture Overview

### Project Structure
```
.
├── public/
│   ├── index.html      # Single-page frontend (HTML + CSS + JavaScript)
│   └── vnc-client.js   # VNC browser client
├── server.js           # Express backend server (HTTP + WebSocket + SSH/SFTP/Docker)
├── local-shell.js      # Local shell module (Linux only)
├── vnc.js              # VNC WebSocket proxy
├── package.json        # Dependency manifest
├── users.json          # User account data (generated at runtime)
└── userdata/           # User data directory (generated at runtime)
```

### Frontend Architecture
- Single-file HTML app with no build step
- Modular JavaScript objects: `State`, `Storage`, `Theme`, `Toast`, `Users`, `Terminal_`, `SFTP`, `Hosts`, `UI`
- CSS variables for theme switching
- Microsoft Fluent Design style

### Backend Architecture
- Express.js HTTP/REST API server
- WebSocket server for SSH connections
- ssh2 library for SSH/SFTP functionality
- File storage for user data and host lists

### Core Modules
1. **UserManager** - User account management (CRUD)
2. **UserDataManager** - User data management (host lists, stats)
3. **SFTP Sessions** - SFTP session management
4. **Guest Sessions** - Guest session management
5. **Docker Stats** - Docker container resource monitoring via `docker stats --no-stream`

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

- Default account: admin / admin
- Password storage: plaintext (use bcrypt in production)
- SFTP sessions are stored in memory (Map)
- Guest data is cleared on disconnect
- User data is isolated per user in separate JSON files
