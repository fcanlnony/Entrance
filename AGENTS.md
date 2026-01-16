# Repository Guidelines

## Project Structure & Module Organization
Entrance Tools is a Node/Express monolith. `server.js` owns HTTP/WebSocket routing plus SSH, SFTP, local shell, and VNC wiring, while `local-shell.js` and `vnc.js` isolate feature-specific logic and `vnc-client.js` handles browser plumbing. The SPA UI sits in `index.html` with inline assets; no bundler is involved. Runtime state lives in `users.json` and `userdata/*.json`, created on first boot—never commit real user data. Temporary payloads land under `uploads/` and dependencies live in `node_modules/`.

## Build, Test, and Development Commands
`npm install` sets up Express, ws, ssh2, multer, and archiver.  
`npm start` (and its alias `npm run dev`) executes `server.js` on port 3000; override with `PORT=4000 npm start`.  
`NODE_ENV=development npm start` enables verbose logging; pair with a reverse proxy when deploying publicly.

## Coding Style & Naming Conventions
Backend files use four-space indentation, semicolons, and CommonJS `require` + `module.exports`. Prefer `const`, destructure imports, and group helpers in plain objects (see `UserManager`). Filenames stay kebab-case, whereas functions/variables use lower camelCase. Front-end additions should blend into the Fluent Design theme already defined inside `index.html`. Anytime you add dependencies, re-run `npm install` so `package-lock.json` remains consistent.

## Testing Guidelines
Automated tests are not yet wired in, so validate changes manually: run `npm start`, log in with a disposable or the default `admin/admin` account on a safe machine, and exercise each updated surface (SSH terminal, local shell, VNC, Serial, SFTP). Capture the commands you issued and browsers/OSes used, then paste that checklist into the PR. For new utility modules, add lightweight `node scripts/my-check.js` assertions or document how reviewers can replicate the scenario.

## Commit & Pull Request Guidelines
Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.); keep patches focused and avoid bundling unrelated fixes. PRs should explain the problem, the approach, and the validation evidence (screenshots, terminal recordings, or log snippets). Highlight any migrations touching `users.json`, `userdata/`, or upload behavior so deployers can back up state.

## Security & Configuration Tips
Passwords in `users.json` are plaintext—change the defaults immediately, prefer environment variables for secrets, and scrub sample data before pushing. Sanitize any hostnames or file paths taken from the UI, and develop using a non-privileged system account. Remove throwaway files from `uploads/` and `userdata/` before requesting review.
