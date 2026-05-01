# Entrance Environment Variable Behavior

This document explains how each supported Entrance environment variable changes runtime behavior. Unless noted otherwise, values are read once at process startup, so changing them requires a restart.

## Parsing Rules

| Pattern | Variables | Notes |
| --- | --- | --- |
| `=1` flags | `ENTRANCE_CORS_DISABLE`, `ENTRANCE_DESKTOP_NOLOGIN`, `ENTRANCE_DESKTOP_API_ONLY` | Any value other than `1` is treated as disabled |
| `=true` flags | `STRICT_HOST_KEY_CHECKING`, `ALLOW_PRIVATE_NETWORKS` | Use the literal string `true` |
| integer values | `PORT`, `AUTH_TOKEN_TTL`, `LOGIN_WINDOW_MS`, `LOGIN_MAX_ATTEMPTS`, `SSH_*_MAX_LENGTH` | Invalid values fall back to the built-in defaults except `PORT`, which throws on invalid input |
| string values | everything else in this document | Empty strings usually fall back to the documented default |

## Startup and Storage

| Variable | Default | Behavior change | Notes |
| --- | --- | --- | --- |
| `PORT` | `3000` | Changes the HTTP listening port | Can also be overridden with `npm start -- --port 4000` |
| `ENTRANCE_HOST` | `0.0.0.0` in web mode, `127.0.0.1` in desktop API-only mode | Changes the bind address | Useful when you want loopback-only or a specific interface |
| `ENTRANCE_DATA_DIR` | repository root | Moves runtime data such as `users.json`, `userdata/`, `known_hosts.json`, `private-networks.json`, `.ssh_password_key`, and `LOGIN_KEEP` | Keep this directory persistent and never commit it |

## Auth and Session

| Variable | Default | Behavior change | Notes |
| --- | --- | --- | --- |
| `AUTH_SECRET` | none, required | Signs auth tokens and derives the key used to encrypt `LOGIN_KEEP` | Changing it invalidates saved browser sessions |
| `SSH_PASSWORD_KEY` | auto-generates `.ssh_password_key` under `ENTRANCE_DATA_DIR` | Encrypts stored SSH/SFTP credentials and the private-network allowlist | If you set it manually, it must remain stable across restarts |
| `AUTH_TOKEN_TTL` | `604800` seconds | Changes the default password-login token lifetime and the default keepalive duration shown to clients | Users can still override the duration from Settings |
| `LOGIN_WINDOW_MS` | `900000` | Changes how long failed login attempts stay inside the rate-limit window | Lower values forgive failures sooner |
| `LOGIN_MAX_ATTEMPTS` | `5` | Changes how many failed logins are allowed inside the rate-limit window | Lower values make login throttling stricter |

## Network Access and Targeting

| Variable | Default | Behavior change | Notes |
| --- | --- | --- | --- |
| `STRICT_HOST_KEY_CHECKING` | `false` | When `true`, SSH connections reject unknown host keys instead of learning them automatically | Better security, more first-connect friction |
| `ALLOWED_TARGETS` | empty | Restricts SSH/VNC targets to a comma-separated allowlist, including `*.example.com` style patterns | When empty, no hostname allowlist is enforced |
| `ALLOW_PRIVATE_NETWORKS` | `false` | When `true`, private IP ranges can be reached directly without the admin-managed private-network allowlist | Useful in trusted lab networks; looser than the default policy |
| `ENTRANCE_CORS_DISABLE` | `0` | When set to `1`, Entrance stops restricting browser `Origin` headers to `localhost`, `127.0.0.1`, or the desktop renderer origin and instead reflects any request origin in CORS responses | Use this when accessing Entrance through a LAN IP, reverse proxy, or tunnel domain. It weakens browser-side origin protection and should stay off unless you need it |

## Desktop Mode and CORS

| Variable | Default | Behavior change | Notes |
| --- | --- | --- | --- |
| `ENTRANCE_DESKTOP_NOLOGIN` | `0` | When `1`, the backend exposes no-login desktop behavior and the UI hides password-change controls | Intended for secure desktop wrappers, not general web exposure |
| `ENTRANCE_DESKTOP_API_ONLY` | `0` | When `1`, Entrance stops serving `public/index.html` and exposes backend APIs only | Also changes the default bind host to `127.0.0.1` |
| `ENTRANCE_DESKTOP_ALLOWED_ORIGIN` | `app://entrance` | Changes which renderer origin is allowed to call the API when desktop API-only mode is active and `ENTRANCE_CORS_DISABLE` is not enabled | Mainly for custom Electron wrapper origins |
| `ENTRANCE_DESKTOP_BOOTSTRAP_SECRET` | empty | Enables secure desktop bootstrap by requiring the wrapper to call `POST /api/auth/desktop/bootstrap` with `X-Entrance-Desktop-Secret` | Required when both desktop API-only mode and desktop no-login are enabled |
| `ENTRANCE_DESKTOP_VERSION` | empty | Changes the desktop version string exposed by `/api/app-info` in desktop no-login mode | Cosmetic/diagnostic metadata for wrappers |

## Input Limits

| Variable | Default | Behavior change | Notes |
| --- | --- | --- | --- |
| `SSH_HOST_MAX_LENGTH` | `255` | Changes the maximum accepted SSH host length | Longer values permit larger inputs before validation fails |
| `SSH_USERNAME_MAX_LENGTH` | `128` | Changes the maximum accepted SSH username length | Mainly useful for unusual enterprise usernames |
| `SSH_PASSWORD_MAX_LENGTH` | `2048` | Changes the maximum accepted SSH password length | Affects request validation only |
| `SSH_PASSPHRASE_MAX_LENGTH` | `4096` | Changes the maximum accepted private-key passphrase length | Affects request validation only |
| `SSH_PRIVATE_KEY_MAX_LENGTH` | `65536` | Changes the maximum accepted SSH private-key text length | Increase only if you intentionally support very large key blobs |

## Practical Guidance

- For normal local/browser use, leave `ENTRANCE_CORS_DISABLE` unset.
- For LAN IP, reverse-proxy, or tunnel access where the browser sends a non-localhost `Origin`, set `ENTRANCE_CORS_DISABLE=1`.
- For secure Electron deployments, prefer `ENTRANCE_DESKTOP_API_ONLY=1`, loopback binding, and `ENTRANCE_DESKTOP_BOOTSTRAP_SECRET` instead of widening CORS.
