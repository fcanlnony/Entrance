# Repository Guidelines

## Project Structure & Module Organization
Entrance Tools is a Node/Express monolith. `server.js` owns HTTP/WebSocket routing plus auth/token signing, SSH, SFTP, local shell, VNC, Docker stats, known-host tracking, and private-network allowlist wiring, while `local-shell.js` provides the cross-platform shell layer (Linux/macOS via `script`, Windows via direct shell spawn), `vnc.js` handles the VNC proxy, and `vnc-client.js` handles browser plumbing. The SPA UI sits in `public/index.html` with inline assets; no bundler is involved. Container deployment assets live in `Dockerfile`, `compose.yml`, and `.dockerignore`. Runtime state lives in `users.json`, `userdata/*.json`, `known_hosts.json`, `private-networks.json`, and `.ssh_password_key` under `ENTRANCE_DATA_DIR` (default repo root); never commit real user data or generated secrets. Temporary payloads land under `uploads/` and dependencies live in `node_modules/`.

The frontend uses modular JavaScript objects (`State`, `Storage`, `Theme`, `Settings`, `Toast`, `Terminal_`, `SFTP`, `Hosts`, `UI`) with CSS variables for theming. Color schemes are applied via a `data-color-scheme` attribute on `<html>` (valid values: `default`, `sakura`, `ocean`, `forest`, `twilight`, `amber`) and work orthogonally with the `data-theme` light/dark toggle. The `Settings` module provides an in-app password change form (calls `PUT /api/users/:username/password`) and a color scheme picker; in `ENTRANCE_DESKTOP_NOLOGIN` mode, the password form is hidden and replaced with a notice.

The SSH view includes three collapsible monitoring panels below the terminal: System Stats (CPU/Memory/Disk I/O line chart, 1s interval), TOP process list (2s interval), and Docker Stats (container resource ring charts for CPU/MEM/NET IO/BLOCK IO, 3s interval with total/single-container view modes). All panels share the same polling pattern: server-side `collectXxx()` via `sshClient.exec()` → `setInterval` → WebSocket push → client `handleXxx()` → DOM render.

## Build, Test, and Development Commands
`npm install` sets up Express, ws, ssh2, multer, archiver, and argon2.
`npm start` (and its alias `npm run dev`) executes `server.js` on port 3000; override with `PORT=4000 npm start`.
`docker build -t entrance-tools .` builds the container image, while `docker compose up -d --build` uses `compose.yml` and persists data under `./data`; Podman users can substitute `docker` with `podman` for equivalent build/run flows.
`NODE_ENV=development npm start` enables verbose logging; pair with a reverse proxy when deploying publicly.

## Environment Variables
- `AUTH_SECRET` is required and signs auth tokens.
- `SSH_PASSWORD_KEY` encrypts stored SSH credentials and private-network allowlists; if omitted, the server writes a generated key to `.ssh_password_key` under `ENTRANCE_DATA_DIR`.
- `ENTRANCE_DATA_DIR` relocates runtime state such as `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, and `.ssh_password_key`.
- Security and targeting knobs include `AUTH_TOKEN_TTL`, `LOGIN_WINDOW_MS`, `LOGIN_MAX_ATTEMPTS`, `STRICT_HOST_KEY_CHECKING`, `ALLOWED_TARGETS`, `ALLOW_PRIVATE_NETWORKS`, and `ENTRANCE_DESKTOP_NOLOGIN`.

## Coding Style & Naming Conventions
Backend files use four-space indentation, semicolons, and CommonJS `require` + `module.exports`. Prefer `const`, destructure imports, and group helpers in plain objects (see `UserManager`). Filenames stay kebab-case, whereas functions/variables use lower camelCase. Front-end additions should blend into the Fluent Design theme already defined inside `index.html`. Anytime you add dependencies, re-run `npm install` so `package-lock.json` remains consistent.

## Testing Guidelines
Automated tests are not yet wired in, so validate changes manually: run `npm start` or the relevant container flow, log in with a disposable or the default `admin/admin` account on a safe machine, and exercise each updated surface (SSH terminal, local shell on the target OS, VNC, Serial, SFTP, and private-network management when touched). Capture the commands you issued and browsers/OSes used, then paste that checklist into the PR. For new utility modules, add lightweight `node scripts/my-check.js` assertions or document how reviewers can replicate the scenario.

## Commit & Pull Request Guidelines
Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.); keep patches focused and avoid bundling unrelated fixes. PRs should explain the problem, the approach, and the validation evidence (screenshots, terminal recordings, or log snippets). Highlight any migrations touching `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, `.ssh_password_key`, or container deployment behavior so deployers can back up state. When adding new SSH monitoring panels, follow the existing collectXxx/startXxx/stopXxx/refreshXxx pattern in both `server.js` and the `Terminal_` object in `index.html`.

## Security & Configuration Tips
Passwords in `users.json` are Argon2id hashes, not plaintext. Stored SSH credentials and private-network allowlists are AES-256-GCM encrypted with `SSH_PASSWORD_KEY` (or the generated `.ssh_password_key`), so treat key rotation as a migration. Prefer environment variables for `AUTH_SECRET`, `SSH_PASSWORD_KEY`, `ENTRANCE_DATA_DIR`, host allowlisting, and login throttling. Sanitize any hostnames or file paths taken from the UI, keep private-network rules narrow, and develop using a non-privileged system account. Remove throwaway files from `uploads/`, `userdata/`, and generated runtime JSON before requesting review.
